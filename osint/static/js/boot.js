/* Runs in <head> before first paint so theme/density never flash. No inline script (CSP). */
(function () {
  var root = document.documentElement;
  try {
    root.setAttribute("data-theme", localStorage.getItem("osint-theme") === "light" ? "light" : "dark");
    var d = localStorage.getItem("osint-density");
    if (d === "compact") root.setAttribute("data-density", "compact");
  } catch (e) {
    root.setAttribute("data-theme", "dark");
  }
})();
