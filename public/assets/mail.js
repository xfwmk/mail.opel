(() => {
  "use strict";
  const $ = id => document.getElementById(id);
  const app = document.querySelector(".app");
  const labels = { INBOX: "Inbox", STARRED: "Starred", SENT: "Sent", ALL: "All mail", TRASH: "Trash" };
  let folder = "INBOX", query = "", page = null, currentId = null, current = null, loading = false;

  async function api(path, options) {
    const response = await fetch(path, { credentials: "same-origin", cache: "no-store", ...options });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || `Request failed (${response.status})`);
    return result;
  }

  const e = (tag, className, content) => {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (content !== undefined) el.textContent = content;
    return el;
  };
  function formatDate(s) {
    const d = new Date(Number(s));
    if (Number.isNaN(d.getTime())) return "";
    return new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }).format(d);
  }
  function notice(text, show = true) {
    $("notice").replaceChildren();
    if (text) $("notice").textContent = text;
    $("notice").hidden = !show;
  }
  function disconnected() {
    notice("Connect Gmail to open your private mailbox.");
    const link = e("a", "", "Connect Gmail ↗");
    link.href = "/auth/google";
    $("notice").append(document.createTextNode(" "), link);
  }
  function renderList(messages, append = false) {
    if (!append) $("messages").replaceChildren();
    for (const m of messages) {
      const button = e("button", `message${m.unread ? " unread" : ""}${m.id === currentId ? " active" : ""}`);
      button.type = "button";
      const top = e("div", "message-top");
      top.append(e("span", "message-from", folder === "SENT" ? m.to : m.from), e("time", "message-date", formatDate(m.date)));
      button.append(top, e("span", "message-subject", `${m.starred ? "★ " : ""}${m.subject}`), e("span", "message-snippet", m.snippet));
      button.addEventListener("click", () => openMessage(m.id));
      $("messages").append(button);
    }
    if (!messages.length && !append) notice("No messages here.");
  }
  async function load(append = false) {
    if (loading) return;
    loading = true;
    $("refresh").disabled = true;
    notice("Loading messages…");
    try {
      const params = new URLSearchParams({ folder });
      if (query) params.set("q", query);
      if (append && page) params.set("page", page);
      const result = await api(`/api/messages?${params}`);
      page = result.nextPageToken;
      $("load-more").hidden = !page;
      renderList(result.messages || [], append);
      if (result.messages?.length) notice("", false);
      $("message-count").textContent = `${result.messages?.length || 0}${page ? "+" : ""}`;
    } catch (err) {
      if (/connect|expired/i.test(err.message)) disconnected();
      else notice(err.message);
    } finally { loading = false; $("refresh").disabled = false; }
  }
  async function openMessage(id) {
    currentId = id;
    app.classList.add("reading");
    $("reader-empty").hidden = false;
    $("reader-empty").textContent = "Loading message…";
    $("reader-content").hidden = true;
    try {
      const m = await api(`/api/messages/${encodeURIComponent(id)}`);
      if (currentId !== id) return;
      current = m;
      $("read-subject").textContent = m.subject;
      $("read-from").textContent = m.from;
      $("read-to").textContent = `To: ${m.to}`;
      $("read-date").textContent = formatDate(m.date);
      $("read-body").textContent = m.body;
      $("star").textContent = m.starred ? "★ Unstar" : "☆ Star";
      $("mark-read").textContent = m.unread ? "Mark read" : "Mark unread";
      $("reader-empty").hidden = true;
      $("reader-content").hidden = false;
      document.querySelectorAll(".message").forEach(button => button.classList.remove("active"));
      // Keep 'unread' unchanged until user explicitly marks it read.
    } catch (err) { $("reader-empty").textContent = err.message; }
  }
  async function action(name) {
    if (!current) return;
    const id = current.id;
    try {
      await api(`/api/messages/${encodeURIComponent(id)}/action`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: name })
      });
      if (name === "trash" || name === "archive") {
        current = null; currentId = null; $("reader-content").hidden = true;
        $("reader-empty").textContent = "Select a message to read it.";
        $("reader-empty").hidden = false;
        app.classList.remove("reading");
      } else {
        current.unread = name === "unread" ? true : name === "read" ? false : current.unread;
        current.starred = name === "star" ? true : name === "unstar" ? false : current.starred;
        $("star").textContent = current.starred ? "★ Unstar" : "☆ Star";
        $("mark-read").textContent = current.unread ? "Mark read" : "Mark unread";
      }
      await load();
    } catch (err) { alert(err.message); }
  }

  document.querySelectorAll("[data-folder]").forEach(button => button.addEventListener("click", () => {
    folder = button.dataset.folder;
    query = ""; page = null; current = null; currentId = null;
    $("search").value = "";
    $("folder-name").textContent = labels[folder];
    $("reader-content").hidden = true;
    $("reader-empty").hidden = false;
    $("reader-empty").textContent = "Select a message to read it.";
    app.classList.remove("reading");
    document.querySelectorAll("[data-folder]").forEach(b => b.classList.toggle("active", b === button));
    load();
  }));
  $("search-form").addEventListener("submit", event => { event.preventDefault(); query = $("search").value.trim(); page = null; load(); });
  $("refresh").addEventListener("click", () => { page = null; load(); });
  $("load-more").addEventListener("click", () => load(true));
  $("back").addEventListener("click", () => app.classList.remove("reading"));
  $("star").addEventListener("click", () => action(current?.starred ? "unstar" : "star"));
  $("mark-read").addEventListener("click", () => action(current?.unread ? "read" : "unread"));
  $("archive").addEventListener("click", () => action("archive"));
  $("trash").addEventListener("click", () => action("trash"));

  const dialog = $("compose-dialog");
  $("compose-open").addEventListener("click", () => { $("compose-status").textContent = ""; dialog.showModal(); });
  $("compose-close").addEventListener("click", () => dialog.close());
  $("compose-form").addEventListener("submit", async event => {
    event.preventDefault();
    $("send").disabled = true;
    $("compose-status").textContent = "Sending…";
    try {
      await api("/api/send", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ to: $("to").value, subject: $("subject").value, body: $("body").value })
      });
      $("compose-form").reset();
      dialog.close();
      page = null;
      if (folder === "SENT") await load();
    } catch (err) { $("compose-status").textContent = err.message; }
    finally { $("send").disabled = false; }
  });

  (async () => {
    try {
      const status = await api("/api/status");
      $("account").textContent = status.connected ? status.email : "Gmail not connected";
      if (status.connected) await load(); else disconnected();
    } catch (err) { notice(err.message); }
  })();
})();
