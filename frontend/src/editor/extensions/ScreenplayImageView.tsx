import React, { useMemo, useRef, useCallback } from 'react';
import { NodeViewWrapper, type NodeViewProps } from '@tiptap/react';
import { api } from '../../services/api';
import { AuthenticatedAssetImage } from '../../components/AuthenticatedAssetImage';

const LINE_HEIGHT_PX = 16; // 12pt — matches pagination LINE_HEIGHT_PT

/**
 * React NodeView for the screenplayImage node. Resolves the asset URL (or falls
 * back to an inline data URL), renders the image at its stored width with simple
 * corner resizing, and records an estimated height (in screenplay lines) so the
 * paginator can roughly account for the image.
 */
export const ScreenplayImageView: React.FC<NodeViewProps> = ({ node, updateAttributes, selected, editor }) => {
  const { assetId, projectId, src, filename, width, align } = node.attrs as {
    assetId: string | null; projectId: string | null; src: string | null;
    filename: string | null; width: number | null; align: string;
  };
  const imgRef = useRef<HTMLImageElement>(null);

  const sourceUrl = useMemo(() => {
    if (src) return src;
    if (assetId && projectId) {
      try { return api.getAssetUrl(projectId, assetId, filename || undefined); } catch { return ''; }
    }
    return '';
  }, [src, assetId, projectId, filename]);

  // On first load (no stored width), default to the natural width capped to the
  // content column, and record the rendered height in lines for pagination.
  const onLoad = useCallback(() => {
    const img = imgRef.current;
    if (!img) return;
    const colWidth = (img.closest('.ProseMirror') as HTMLElement | null)?.clientWidth || 600;
    const naturalW = img.naturalWidth || 300;
    const w = width && width > 0 ? width : Math.min(naturalW, Math.round(colWidth * 0.9));
    const renderedH = (img.naturalHeight / (img.naturalWidth || 1)) * w;
    const heightLines = Math.max(1, Math.ceil(renderedH / LINE_HEIGHT_PX) + 1);
    if (!width || node.attrs.heightLines !== heightLines) {
      updateAttributes({ width: w, heightLines });
    }
  }, [width, node.attrs.heightLines, updateAttributes]);

  // Corner resize: drag to set width; height-in-lines is recomputed from aspect.
  const startResize = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    const img = imgRef.current;
    if (!img) return;
    const startX = e.clientX;
    const startW = width || img.clientWidth;
    const aspect = (img.naturalHeight || 1) / (img.naturalWidth || 1);
    const onMove = (me: MouseEvent) => {
      const w = Math.max(40, Math.round(startW + (me.clientX - startX)));
      const heightLines = Math.max(1, Math.ceil((w * aspect) / LINE_HEIGHT_PX) + 1);
      updateAttributes({ width: w, heightLines });
    };
    const onUp = () => {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
  }, [width, updateAttributes]);

  const editable = editor.isEditable;

  return (
    <NodeViewWrapper
      className={`sp-image align-${align || 'center'}${selected ? ' is-selected' : ''}`}
      data-drag-handle
    >
      <span className="sp-image-inner" style={{ width: width ? `${width}px` : undefined }}>
        <AuthenticatedAssetImage
          ref={imgRef}
          src={sourceUrl}
          alt=""
          draggable={false}
          onLoad={onLoad}
          className="sp-image-img"
        />
        {selected && editable && (
          <span className="sp-image-resize" onMouseDown={startResize} title="Drag to resize" />
        )}
      </span>
    </NodeViewWrapper>
  );
};
