'use strict';

// Runs in <head>, before the page draws. A theme chosen with the sidebar
// toggle (saved in this browser) wins; otherwise Dit follows the system setting.
(function () {
  var theme = null;
  try { theme = localStorage.getItem('dit-theme'); } catch (e) {}
  if (theme !== 'light' && theme !== 'dark') {
    theme = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  document.documentElement.dataset.theme = theme;
})();
