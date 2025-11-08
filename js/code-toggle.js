(function () {
  const capitalizeLanguage = (raw) => {
    if (!raw) return "";
    const cleaned = raw.replace(/^(lang|language)-/i, "");
    if (!cleaned) return "";
    if (cleaned.length <= 3) {
      return cleaned.toUpperCase();
    }
    return cleaned.charAt(0).toUpperCase() + cleaned.slice(1);
  };

  const resolveLanguageLabel = (block) => {
    const codeEl = block.querySelector("code") || block;
    if (!codeEl || !codeEl.classList) {
      return "";
    }

    const langClass = Array.from(codeEl.classList).find((cls) =>
      /^(lang|language)-/.test(cls)
    );

    if (!langClass) {
      return "";
    }

    return capitalizeLanguage(langClass);
  };

  document.addEventListener("DOMContentLoaded", () => {
    const articles = document.querySelectorAll("article.post, article.page");
    if (!articles.length) {
      return;
    }

    let panelIndex = 0;

    articles.forEach((article) => {
      // Remove any existing code-toggle wrappers to prevent nesting
      const existingToggles = article.querySelectorAll(".code-toggle");
      existingToggles.forEach((toggle) => {
        const panel = toggle.querySelector(".code-toggle__panel");
        if (panel) {
          // Move all children of the panel back to the toggle's position
          while (panel.firstChild) {
            const child = panel.firstChild;
            if (child.nodeType === Node.ELEMENT_NODE) {
              child.removeAttribute("data-code-toggle-processed");
            }
            toggle.parentNode.insertBefore(child, toggle);
          }
        }
        toggle.remove();
      });

      const candidates = Array.from(
        article.querySelectorAll(".highlight, pre")
      );

      if (!candidates.length) {
        return;
      }

      const seen = new Set();
      const blocks = [];

      candidates.forEach((candidate) => {
        const container =
          candidate.closest("div[class*='language-']") ||
          candidate.closest("figure.highlight") ||
          candidate;

        if (!container) {
          return;
        }

        if (seen.has(container)) {
          return;
        }

        if (container.closest(".code-toggle")) {
          return;
        }

        if (container.hasAttribute("data-code-toggle-processed")) {
          return;
        }

        seen.add(container);
        blocks.push(container);
      });

      if (!blocks.length) {
        return;
      }

      blocks.forEach((block) => {
        const wrapper = document.createElement("div");
        wrapper.className = "code-toggle";

        const button = document.createElement("button");
        button.type = "button";
        button.className = "code-toggle__button";

        const languageLabel = resolveLanguageLabel(block);
        const showLabel = languageLabel
          ? `Show ${languageLabel} snippet`
          : "Show code";
        const hideLabel = languageLabel
          ? `Hide ${languageLabel} snippet`
          : "Hide code";

        const labelSpan = document.createElement("span");
        labelSpan.className = "code-toggle__label";
        labelSpan.textContent = showLabel;
        button.appendChild(labelSpan);

        const panel = document.createElement("div");
        panel.className = "code-toggle__panel";
        const panelId = `code-toggle-panel-${++panelIndex}`;
        panel.id = panelId;

        button.setAttribute("aria-controls", panelId);
        button.setAttribute("aria-expanded", "false");
        panel.hidden = true;

        button.addEventListener("click", () => {
          const expanded = button.getAttribute("aria-expanded") === "true";
          button.setAttribute("aria-expanded", String(!expanded));
          panel.hidden = expanded;
          labelSpan.textContent = expanded ? showLabel : hideLabel;
        });

        const parent = block.parentNode;
        parent.insertBefore(wrapper, block);
        wrapper.appendChild(button);
        wrapper.appendChild(panel);
        panel.appendChild(block);

        // Mark the block as processed
        block.setAttribute("data-code-toggle-processed", "true");
      });

      // Mark the article as processed
      article.setAttribute("data-code-toggle-processed", "true");
    });
  });
})();
