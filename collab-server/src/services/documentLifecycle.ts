import type { Hocuspocus } from '@hocuspocus/server';

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

/**
 * Close a room and wait until Hocuspocus has finished any pending store and
 * removed the in-memory Y.Doc. Returning before unload makes reset racy: a
 * late onStoreDocument can recreate the file that the reset just deleted.
 */
export async function closeAndAwaitDocumentUnload(
  server: Hocuspocus,
  documentName: string,
  timeoutMs = 5_000,
  pollIntervalMs = 10,
): Promise<boolean> {
  const storeId = `onStoreDocument-${documentName}`;
  const deadline = Date.now() + timeoutMs;

  while (Date.now() <= deadline) {
    // Authentication may have begun loading a document just before the reset
    // guard was installed. Wait for that promise to settle before deleting.
    if (server.loadingDocuments.has(documentName)) {
      await delay(pollIntervalMs);
      continue;
    }

    const document = server.documents.get(documentName);
    if (!document) return true;
    server.closeConnections(documentName);

    // Flush a scheduled store rather than waiting for its debounce timer.
    if (server.debouncer.isDebounced(storeId)) {
      await Promise.resolve(server.debouncer.executeNow(storeId));
    }

    const busy =
      server.debouncer.isDebounced(storeId)
      || server.debouncer.isCurrentlyExecuting(storeId)
      || document.saveMutex.isLocked()
      || document.getConnectionsCount() > 0;

    if (!busy) {
      await server.unloadDocument(document);
      if (
        !server.loadingDocuments.has(documentName)
        && !server.documents.has(documentName)
      ) return true;
    }

    await delay(pollIntervalMs);
  }

  return false;
}
