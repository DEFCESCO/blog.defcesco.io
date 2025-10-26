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
      const blocks = Array.from(
        article.querySelectorAll(".highlight, pre")
      ).filter((block) => {
        if (block.closest(".code-toggle")) {
          return false;
        }

        if (block.classList.contains("highlight")) {
          if (block.tagName && block.tagName.toLowerCase() === "pre") {
            return false;
          }

          const ancestorHighlight = block.parentElement?.closest(".highlight");
          if (ancestorHighlight && ancestorHighlight !== block) {
            return false;
          }

          return true;
        }

        return !block.closest(".highlight");
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
      });
    });
  });
})();
