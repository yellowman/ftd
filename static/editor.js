// Self-hosted WYSIWYG editor for mailing bodies and direct customer emails.
//
// Progressive enhancement over the plain body_html textarea: without this
// script the form still works. The contenteditable surface is the authoring
// view; its HTML is synced into the (hidden) textarea, which remains the only
// thing the form submits. An "HTML source" toggle exposes the textarea for
// hand editing.
//
// The toolbar is built here (single source of truth for every page that
// embeds an editor): block-format select, grouped commands with active-state
// highlighting, inline URL dialogs (no window.prompt), and the standard
// shortcuts (Ctrl+B/I/U, Ctrl+K for links).
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
	var savedRange = null;
	var stateButtons = [];

	function escapeHTML(s) {
		return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
	}

	function syncFromEditor() {
		if (!rawMode) {
			textarea.value = editor.innerHTML;
		}
	}

	function exec(cmd, val) {
		editor.focus();
		document.execCommand(cmd, false, val || null);
		syncFromEditor();
		refreshState();
	}

	// ---- selection bookkeeping (dialogs steal focus) ----

	function rememberSelection() {
		var sel = window.getSelection();
		if (sel.rangeCount > 0 && editor.contains(sel.anchorNode)) {
			savedRange = sel.getRangeAt(0).cloneRange();
		}
	}

	function restoreSelection() {
		editor.focus();
		if (savedRange) {
			var sel = window.getSelection();
			sel.removeAllRanges();
			sel.addRange(savedRange);
		}
	}

	// ---- toolbar ----

	var BLOCKS = [
		["p", "Paragraph"],
		["h2", "Heading"],
		["h3", "Subheading"],
		["blockquote", "Quote"],
	];

	var GROUPS = [
		[
			{ cmd: "bold", label: "<b>B</b>", title: "Bold (Ctrl+B)", state: "bold" },
			{ cmd: "italic", label: "<i>I</i>", title: "Italic (Ctrl+I)", state: "italic" },
			{ cmd: "underline", label: "<u>U</u>", title: "Underline (Ctrl+U)", state: "underline" },
			{ cmd: "strikeThrough", label: "<s>S</s>", title: "Strikethrough", state: "strikeThrough" },
		],
		[
			{ cmd: "insertUnorderedList", label: "• List", title: "Bullet list", state: "insertUnorderedList" },
			{ cmd: "insertOrderedList", label: "1. List", title: "Numbered list", state: "insertOrderedList" },
		],
		[
			{ act: "link", label: "Link", title: "Insert link (Ctrl+K)" },
			{ cmd: "unlink", label: "Unlink", title: "Remove link" },
			{ act: "image", label: "Image", title: "Insert image by URL" },
			{ act: "cta", label: "Button", title: "Insert call-to-action button" },
		],
		[
			{ cmd: "insertHorizontalRule", label: "―", title: "Divider" },
			{ cmd: "removeFormat", label: "Clear", title: "Clear formatting" },
		],
		[
			{ cmd: "undo", label: "↶", title: "Undo (Ctrl+Z)" },
			{ cmd: "redo", label: "↷", title: "Redo (Ctrl+Shift+Z)" },
		],
	];

	var blockSelect = document.createElement("select");
	blockSelect.title = "Paragraph format";
	BLOCKS.forEach(function (b) {
		var opt = document.createElement("option");
		opt.value = b[0];
		opt.textContent = b[1];
		blockSelect.appendChild(opt);
	});
	blockSelect.addEventListener("change", function () {
		exec("formatBlock", "<" + blockSelect.value + ">");
	});
	toolbar.appendChild(blockSelect);

	GROUPS.forEach(function (group) {
		var sep = document.createElement("span");
		sep.className = "tb-sep";
		toolbar.appendChild(sep);
		group.forEach(function (spec) {
			var btn = document.createElement("button");
			btn.type = "button";
			btn.innerHTML = spec.label;
			btn.title = spec.title;
			// mousedown would move focus out of the editor and drop the
			// selection the command should apply to.
			btn.addEventListener("mousedown", function (e) { e.preventDefault(); });
			btn.addEventListener("click", function (e) {
				e.preventDefault();
				if (spec.act) {
					openDialog(spec.act);
				} else {
					exec(spec.cmd);
				}
			});
			if (spec.state) {
				btn.setAttribute("data-state", spec.state);
				stateButtons.push(btn);
			}
			toolbar.appendChild(btn);
		});
	});

	function refreshState() {
		stateButtons.forEach(function (btn) {
			var on = false;
			try { on = document.queryCommandState(btn.getAttribute("data-state")); } catch (err) { /* unsupported */ }
			btn.classList.toggle("active", on);
		});
		try {
			var block = String(document.queryCommandValue("formatBlock")).toLowerCase();
			for (var i = 0; i < blockSelect.options.length; i++) {
				if (blockSelect.options[i].value === block) {
					blockSelect.value = block;
					return;
				}
			}
			blockSelect.value = "p";
		} catch (err) { /* unsupported */ }
	}

	document.addEventListener("selectionchange", function () {
		var sel = window.getSelection();
		if (sel.anchorNode && editor.contains(sel.anchorNode)) {
			refreshState();
		}
	});

	// ---- inline dialog (replaces window.prompt) ----

	var DIALOGS = {
		link: {
			fields: [{ name: "url", label: "Link URL", placeholder: "https://example.com/page" }],
			apply: function (v) {
				var url = normalizeURL(v.url);
				if (!url) return;
				restoreSelection();
				var sel = window.getSelection();
				if (!sel.rangeCount || sel.getRangeAt(0).collapsed) {
					document.execCommand("insertHTML", false,
						'<a href="' + escapeHTML(url) + '">' + escapeHTML(url) + "</a>");
				} else {
					document.execCommand("createLink", false, url);
				}
			},
		},
		image: {
			fields: [{ name: "src", label: "Image URL", placeholder: "https://… or use the media library below" }],
			apply: function (v) {
				var src = normalizeURL(v.src);
				if (!src) return;
				restoreSelection();
				document.execCommand("insertHTML", false,
					'<img src="' + escapeHTML(src) + '" alt="" style="max-width:100%">');
			},
		},
		cta: {
			fields: [
				{ name: "href", label: "Button link URL", placeholder: "https://example.com/offer" },
				{ name: "label", label: "Button text", placeholder: "Learn more" },
			],
			apply: function (v) {
				var href = normalizeURL(v.href);
				var label = (v.label || "").trim();
				if (!href || !label) return;
				restoreSelection();
				// Inline styles: email clients ignore stylesheets.
				document.execCommand("insertHTML", false,
					'<p><a href="' + escapeHTML(href) + '" ' +
					'style="display:inline-block;background:#4f46e5;color:#ffffff;' +
					'padding:10px 22px;border-radius:6px;text-decoration:none;' +
					'font-weight:bold">' + escapeHTML(label) + "</a></p>");
			},
		},
	};

	function normalizeURL(raw) {
		var url = (raw || "").trim();
		if (!url) return "";
		if (/^(https?:\/\/|mailto:)/i.test(url)) return url;
		if (/^[a-z][a-z0-9+.-]*:/i.test(url)) return ""; // refuse javascript: and friends
		return "https://" + url;
	}

	var panel = document.createElement("div");
	panel.className = "editor-panel";
	panel.hidden = true;
	toolbar.insertAdjacentElement("afterend", panel);

	function closeDialog() {
		panel.hidden = true;
		panel.innerHTML = "";
	}

	function openDialog(kind) {
		rememberSelection();
		var spec = DIALOGS[kind];
		panel.innerHTML = "";
		var inputs = {};
		spec.fields.forEach(function (f) {
			var lab = document.createElement("label");
			lab.textContent = f.label;
			var inp = document.createElement("input");
			inp.type = "text";
			inp.placeholder = f.placeholder || "";
			lab.appendChild(inp);
			panel.appendChild(lab);
			inputs[f.name] = inp;
		});
		var ok = document.createElement("button");
		ok.type = "button";
		ok.textContent = "Insert";
		var cancel = document.createElement("button");
		cancel.type = "button";
		cancel.textContent = "Cancel";
		cancel.className = "panel-cancel";
		panel.appendChild(ok);
		panel.appendChild(cancel);

		function submit() {
			var values = {};
			for (var k in inputs) values[k] = inputs[k].value;
			closeDialog();
			spec.apply(values);
			syncFromEditor();
			refreshState();
		}
		ok.addEventListener("click", submit);
		cancel.addEventListener("click", function () { closeDialog(); editor.focus(); });
		panel.addEventListener("keydown", function (e) {
			if (e.key === "Enter") { e.preventDefault(); submit(); }
			if (e.key === "Escape") { e.preventDefault(); closeDialog(); editor.focus(); }
		});
		panel.hidden = false;
		spec.fields.length && inputs[spec.fields[0].name].focus();
	}

	// ---- shortcuts ----

	editor.addEventListener("keydown", function (e) {
		if ((e.ctrlKey || e.metaKey) && !e.altKey && e.key.toLowerCase() === "k") {
			e.preventDefault();
			openDialog("link");
		}
	});

	// ---- activate rich mode ----

	editor.innerHTML = textarea.value;
	editor.setAttribute("data-placeholder", "Write your email…");
	wrap.classList.add("rich");
	toolbar.hidden = false;
	editor.hidden = false;
	if (rawToggle) {
		rawToggle.hidden = false;
	}

	editor.addEventListener("input", syncFromEditor);
	form.addEventListener("submit", syncFromEditor);
	refreshState();

	if (rawToggle) {
		rawToggle.addEventListener("click", function (e) {
			e.preventDefault();
			rawMode = !rawMode;
			closeDialog();
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
