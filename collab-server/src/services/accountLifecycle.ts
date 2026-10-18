export interface GuardResult<T> {
  accepted: boolean;
  value?: T;
}

/**
 * Serializes account deletion against authenticated writes for one user.
 * Deleted user ids remain tombstoned for the process lifetime; UUID ids are
 * never reused, and the database owner-existence check is the cross-process
 * backstop after a restart.
 */
export class AccountLifecycleGuard {
  private readonly tails = new Map<string, Promise<void>>();
  private readonly deletedUsers = new Set<string>();

  private async locked<T>(userId: string, operation: () => Promise<T>): Promise<T> {
    const previous = this.tails.get(userId) ?? Promise.resolve();
    let release!: () => void;
    const current = new Promise<void>((resolve) => { release = resolve; });
    this.tails.set(userId, current);
    await previous;
    try {
      return await operation();
    } finally {
      release();
      if (this.tails.get(userId) === current) this.tails.delete(userId);
    }
  }

  async runActive<T>(
    userId: string,
    operation: () => Promise<T>,
  ): Promise<GuardResult<T>> {
    return this.locked(userId, async () => {
      if (this.deletedUsers.has(userId)) return { accepted: false };
      return { accepted: true, value: await operation() };
    });
  }

  async runDeletion<T>(
    userId: string,
    operation: (markDeletionMayHaveOccurred: () => void) => Promise<T>,
  ): Promise<GuardResult<T>> {
    return this.locked(userId, async () => {
      if (this.deletedUsers.has(userId)) return { accepted: false };
      // Block new work immediately. A failure before the owner DELETE is
      // issued is retryable; after that point database outcome may be
      // uncertain, so the process-lifetime tombstone must fail closed.
      this.deletedUsers.add(userId);
      let deletionMayHaveOccurred = false;
      try {
        const value = await operation(() => {
          deletionMayHaveOccurred = true;
        });
        return { accepted: true, value };
      } catch (error) {
        if (!deletionMayHaveOccurred) this.deletedUsers.delete(userId);
        throw error;
      }
    });
  }
}

export const accountLifecycle = new AccountLifecycleGuard();
