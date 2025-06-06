function getFingerprint() {
  const ua = navigator.userAgent;
  const lang = navigator.language || '';
  const scr = window.screen || {};
  const res = scr.width + 'x' + scr.height + 'x' + (scr.colorDepth || 0);
  return btoa(ua + lang + res);
}
