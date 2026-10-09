'use strict';
/**
 * 零依赖的多部件（multipart/form-data）解析。
 * 用于在 pkg 单文件二进制里接收 PCAP 上传，无需 busboy/multer 等外部依赖。
 * 仅按 RFC7574 标准结构解析，支持多字段、文件字段（含 filename）与文本字段。
 */

/** 收集原始请求体到 req.rawBody（仅对 multipart 生效） */
function rawBody(maxBytes = 200 * 1024 * 1024) {
  return (req, res, next) => {
    const ct = req.headers['content-type'] || '';
    if (!ct.includes('multipart/form-data')) return next();
    const chunks = [];
    let size = 0;
    let aborted = false;
    req.on('data', (c) => {
      if (aborted) return;
      size += c.length;
      if (size > maxBytes) {
        aborted = true;
        return next(new Error('上传体过大（上限 ' + Math.round(maxBytes / 1048576) + 'MB）'));
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (aborted) return;
      req.rawBody = Buffer.concat(chunks);
      next();
    });
    req.on('error', () => next(new Error('读取上传流失败')));
  };
}

/**
 * 解析 multipart 原始体
 * @returns {Array<{name:string,filename?:string,contentType?:string,data:Buffer}>}
 */
function parse(buf, contentType) {
  const m = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType || '');
  if (!m) throw new Error('multipart 缺少 boundary');
  const boundary = '--' + (m[1] || m[2]).trim();
  const parts = [];
  const bBuf = Buffer.from(boundary);
  let start = buf.indexOf(bBuf);
  if (start < 0) return parts;
  while (start >= 0) {
    // 定位本段结束的 \r\n\r\n（头体分隔）
    const headerEnd = buf.indexOf('\r\n\r\n', start + bBuf.length);
    if (headerEnd < 0) break;
    // 下一段 boundary 起点
    const nextBoundary = buf.indexOf(bBuf, headerEnd);
    if (nextBoundary < 0) break;
    const header = buf.toString('latin1', start + bBuf.length + 2, headerEnd);
    const bodyStart = headerEnd + 4;
    let bodyEnd = nextBoundary - 2; // 去掉段尾的 \r\n
    if (bodyEnd < bodyStart) bodyEnd = bodyStart;
    const body = buf.subarray(bodyStart, bodyEnd);
    const cd = /content-disposition:[^\r\n]*/i.exec(header);
    const nameM = /name="([^"]*)"/i.exec(cd ? cd[0] : '');
    const fileM = /filename="([^"]*)"/i.exec(cd ? cd[0] : '');
    const ctM = /content-type:\s*([^\r\n]+)/i.exec(header);
    const part = { name: nameM ? nameM[1] : '', data: body };
    if (fileM) part.filename = fileM[1];
    if (ctM) part.contentType = ctM[1].trim();
    parts.push(part);
    start = nextBoundary;
  }
  return parts;
}

module.exports = { rawBody, parse };
