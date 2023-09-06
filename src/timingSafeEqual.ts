export function timingSafeEqual(
  a: ArrayBufferView | ArrayBufferLike | DataView,
  b: ArrayBufferView | ArrayBufferLike | DataView,
): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  let ad: DataView, bd: DataView;
  if (a instanceof DataView) {
    ad = a;
  } else {
    ad = new DataView(ArrayBuffer.isView(a) ? a.buffer : a);
  }
  if (b instanceof DataView) {
    bd = b;
  } else {
    bd = new DataView(ArrayBuffer.isView(b) ? b.buffer : b);
  }
  const length = a.byteLength;
  let out = 0;
  let i = -1;
  while (++i < length) {
    out |= ad.getUint8(i) ^ bd.getUint8(i);
  }
  return out === 0;
}
