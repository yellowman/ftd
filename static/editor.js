// Minimal self-hosted WYSIWYG editor for mailing bodies.
//
// Progressive enhancement over the plain body_html textarea: without this
// script the form still works. The contenteditable surface is the authoring
// view; its HTML is synced into the (hidden) textarea, which remains the only
// thing the form submits. An "HTML source" toggle exposes the textarea for
// hand editing.
(function () {
	"use strict";

	var form = document.getElementById("compose-form");
	var textarea = document.getElementById("body-html");
	var editor = document.getElementById("rich-editor");
	var toolbar = document.getElementById("editor-toolbar");
	var rawToggle = document.getElementById("raw-toggle");
	var wrap = document.getElementById("editor-wrap");
	if (!form || !textarea || !editor || !toolbar || !wrap) {
		return;
	}

	var rawMode = false;

	function escapeHTML(s) {
		return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
	}

	function syncFromEditor() {
		if (!rawMode) {
			textarea.value = editor.innerHTML;
		}
	}

	// Activate rich mode.
	editor.innerHTML = textarea.value;
	wrap.classList.add("rich");
	toolbar.hidden = false;
	editor.hidden = false;
	if (rawToggle) {
		rawToggle.hidden = false;
	}

	editor.addEventListener("input", syncFromEditor);
	form.addEventListener("submit", syncFromEditor);

	toolbar.addEventListener("click", function (e) {
		var btn = e.target.closest ? e.target.closest("button[data-cmd]") : null;
		if (!btn) {
			return;
		}
		e.preventDefault();
		var cmd = btn.getAttribute("data-cmd");
		editor.focus();
		switch (cmd) {
		case "h2":
			document.execCommand("formatBlock", false, "<h2>");
			break;
		case "p":
			document.execCommand("formatBlock", false, "<p>");
			break;
		case "link": {
			var url = window.prompt("Link URL (https://…):", "https://");
			if (url) {
				document.execCommand("createLink", false, url);
			}
			break;
		}
		case "image": {
			var src = window.prompt("Image URL:", "https://");
			if (src) {
				document.execCommand("insertImage", false, src);
			}
			break;
		}
		case "cta": {
			var href = window.prompt("Button link URL:", "https://");
			if (!href) {
				break;
			}
			var label = window.prompt("Button text:", "Learn more");
			if (!label) {
				break;
			}
			// Inline styles: email clients ignore stylesheets.
			var html = '<p><a href="' + escapeHTML(href) + '" ' +
				'style="display:inline-block;background:#4f46e5;color:#ffffff;' +
				'padding:10px 22px;border-radius:6px;text-decoration:none;' +
				'font-weight:bold">' + escapeHTML(label) + "</a></p>";
			document.execCommand("insertHTML", false, html);
			break;
		}
		default:
			document.execCommand(cmd, false, null);
		}
		syncFromEditor();
	});

	if (rawToggle) {
		rawToggle.addEventListener("click", function (e) {
			e.preventDefault();
			rawMode = !rawMode;
			if (rawMode) {
				// Entering source view: editor is authoritative.
				textarea.value = editor.innerHTML;
			} else {
				// Leaving source view: textarea is authoritative.
				editor.innerHTML = textarea.value;
			}
			wrap.classList.toggle("raw", rawMode);
			rawToggle.textContent = rawMode ? "Rich editor" : "HTML source";
		});
	}

	// "Insert" buttons in the media library drop the image into the editor.
	document.addEventListener("click", function (e) {
		var btn = e.target.closest ? e.target.closest("button.media-insert") : null;
		if (!btn) {
			return;
		}
		e.preventDefault();
		var src = btn.getAttribute("data-src");
		if (!src) {
			return;
		}
		if (rawMode) {
			textarea.value += '\n<img src="' + src + '" alt="" style="max-width:100%">';
			return;
		}
		editor.focus();
		document.execCommand("insertHTML", false,
			'<img src="' + escapeHTML(src) + '" alt="" style="max-width:100%">');
		syncFromEditor();
	});
})();
