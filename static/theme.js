/* Shared dark/light preference for the console shell and Incident Workspace. */
(function () {
  var KEY = "aegis-theme";

  function current() {
    return document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
  }

  function apply(theme) {
    var next = theme === "light" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem(KEY, next); } catch (e) {}
    var buttons = document.querySelectorAll("[data-theme-toggle]");
    for (var i = 0; i < buttons.length; i++) {
      var light = next === "light";
      buttons[i].textContent = light ? "Dark" : "Light";
      buttons[i].setAttribute("aria-pressed", light ? "true" : "false");
      buttons[i].setAttribute("aria-label", light ? "Switch to dark theme" : "Switch to light theme");
    }
  }

  function preferred() {
    try {
      var stored = localStorage.getItem(KEY);
      if (stored === "light" || stored === "dark") return stored;
    } catch (e) {}
    if (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) return "light";
    return "dark";
  }

  window.aegisToggleTheme = function () {
    apply(current() === "light" ? "dark" : "light");
  };

  apply(preferred());
  document.addEventListener("DOMContentLoaded", function () { apply(current()); });
})();
