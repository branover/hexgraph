import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, JournalEntry } from "../api";
import { Icon } from "./Icon";
import JournalMarkdown from "./JournalMarkdown";
import JournalComposer from "./JournalComposer";

// A relative timestamp ("3m", "2h", "5d") for the entry header — calm, skimmable.
function ago(iso?: string | null): string {
  if (!iso) return "";
  const t = new Date(iso).getTime();
  const s = Math.max(0, (Date.now() - t) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  if (s < 86400 * 7) return `${Math.floor(s / 86400)}d ago`;
  return new Date(iso).toLocaleDateString();
}

// The JOURNAL — the third notebook surface (a right-pane tab alongside findings / hypotheses /
// tasks). A timeline of entries newest-first (author badge human/agent, timestamp, sanitized
// rendered markdown, an "edited" marker, and clickable @-mention chips) + a lean composer that
// appears only when composing. Filter by author / full-text search. Composing posts as the human;
// any entry is editable/deletable from this researcher workbench (design-working-memory.md §5).
export default function JournalPanel({ projectId, onSelectMention }: {
  projectId: string;
  onSelectMention?: (kind: string, id: string) => void;
}) {
  const [entries, setEntries] = useState<JournalEntry[]>([]);
  const [author, setAuthor] = useState<"all" | "human" | "agent">("all");
  const [q, setQ] = useState("");
  const [composing, setComposing] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const searchTimer = useRef<any>();

  const load = useCallback(async () => {
    try {
      const r = q.trim()
        ? await api.searchJournal(projectId, q.trim())
        : await api.journal(projectId, { author: author === "all" ? undefined : author });
      // Search has no author filter server-side; apply it client-side for a consistent UI.
      const rows = q.trim() && author !== "all" ? r.entries.filter((e) => e.author === author) : r.entries;
      setEntries(rows);
    } catch { setEntries([]); }
    finally { setLoaded(true); }
  }, [projectId, author, q]);

  // Debounce the search; reload immediately on author/project change.
  useEffect(() => {
    clearTimeout(searchTimer.current);
    if (q.trim()) { searchTimer.current = setTimeout(load, 200); return () => clearTimeout(searchTimer.current); }
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId, author, q]);

  const counts = useMemo(() => {
    const c = { human: 0, agent: 0 };
    entries.forEach((e) => { c[e.author]++; });
    return c;
  }, [entries]);

  const lastAgent = useMemo(() => entries.find((e) => e.author === "agent"), [entries]);

  const create = async (body: string) => {
    setBusy(true);
    try { await api.createJournalEntry(projectId, body); setComposing(false); await load(); }
    finally { setBusy(false); }
  };
  const saveEdit = async (eid: string, body: string) => {
    setBusy(true);
    try { await api.updateJournalEntry(eid, body); setEditId(null); await load(); }
    finally { setBusy(false); }
  };
  const remove = async (eid: string) => {
    if (!window.confirm("Delete this journal entry? This can't be undone.")) return;
    await api.deleteJournalEntry(eid);
    await load();
  };

  const Entry = (e: JournalEntry) => {
    if (editId === e.id) {
      return (
        <div key={e.id} className="jentry editing">
          <JournalComposer projectId={projectId} initialBody={e.body} busy={busy}
                           onSave={(b) => saveEdit(e.id, b)} onCancel={() => setEditId(null)} />
        </div>
      );
    }
    const agent = e.author === "agent";
    return (
      <div key={e.id} className="jentry fade-in">
        <div className="jentry-h">
          <span className={"jauthor " + e.author} title={agent ? "Written by an agent" : "Written by you"}>
            <Icon name={agent ? "bot" : "user"} size={12} /> {agent ? "agent" : "human"}
          </span>
          <span className="muted jtime" title={e.created_at || ""}><Icon name="clock" size={11} /> {ago(e.created_at)}</span>
          {e.edited && <span className="muted jedited" title={`edited ${ago(e.updated_at)}`}>· edited</span>}
          <span className="grow" />
          <button className="btn sm icon ghost jentry-act" title="Edit entry" onClick={() => setEditId(e.id)}>
            <Icon name="pencil" size={11} />
          </button>
          <button className="btn sm icon ghost danger jentry-act" title="Delete entry" onClick={() => remove(e.id)}>
            <Icon name="x" size={11} />
          </button>
        </div>
        <div className="jbody">
          <JournalMarkdown body={e.body} mentions={e.mentions} onSelect={onSelectMention} />
        </div>
      </div>
    );
  };

  return (
    <>
      <div className="fbar">
        <div className="input" style={{ flex: 1 }}>
          <Icon name="search" size={13} />
          <input placeholder="search the journal…" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <select className="sel" value={author} onChange={(e) => setAuthor(e.target.value as any)} title="filter by author">
          <option value="all">author</option>
          <option value="human">human{counts.human ? ` (${counts.human})` : ""}</option>
          <option value="agent">agent{counts.agent ? ` (${counts.agent})` : ""}</option>
        </select>
        {!composing && !editId && (
          <button className="btn sm primary" onClick={() => setComposing(true)} title="Write a new journal entry">
            <Icon name="plus" size={12} /> Write
          </button>
        )}
      </div>
      {/* Layer-3 staleness surface: how long since the agent last wrote (a trust signal). */}
      {lastAgent && (
        <div className="jstale">
          <Icon name="bot" size={11} /> last agent note {ago(lastAgent.created_at)}
        </div>
      )}
      {composing && (
        <div className="jcompose-wrap">
          <JournalComposer projectId={projectId} busy={busy}
                           onSave={create} onCancel={() => setComposing(false)} />
        </div>
      )}
      <div className="scroll">
        {!loaded && <div className="empty">loading…</div>}
        {loaded && entries.length === 0 && (
          <div className="empty">
            {q.trim()
              ? "No entries match your search."
              : "No journal entries yet. Capture an idea, a dead end, or what you learned — your story alongside the graph."}
          </div>
        )}
        {entries.map(Entry)}
      </div>
    </>
  );
}

// A compact back-reference list — "the narrative trail": journal entries that @-mention a given
// object (node / finding / hypothesis), shown in that object's detail pane (design §5.5). Each
// row links into the entry's body; clicking a different mention chip inside still routes through
// the shared selection plumbing.
export function JournalBackrefs({ projectId, refKind, refId, onSelectMention }: {
  projectId: string; refKind: string; refId: string;
  onSelectMention?: (kind: string, id: string) => void;
}) {
  const [entries, setEntries] = useState<JournalEntry[]>([]);
  const [loaded, setLoaded] = useState(false);
  useEffect(() => {
    let live = true;
    api.journal(projectId, { mentionsKind: refKind, mentionsId: refId, limit: 50 })
      .then((r) => { if (live) { setEntries(r.entries); setLoaded(true); } })
      .catch(() => { if (live) { setEntries([]); setLoaded(true); } });
    return () => { live = false; };
  }, [projectId, refKind, refId]);

  if (!loaded || entries.length === 0) return null;  // quiet when there's no trail
  return (
    <>
      <div className="sec"><Icon name="book" size={11} /> In the journal · {entries.length}</div>
      <div className="jbackrefs">
        {entries.map((e) => (
          <div key={e.id} className="jbackref">
            <div className="jbackref-h">
              <span className={"jauthor sm " + e.author}>
                <Icon name={e.author === "agent" ? "bot" : "user"} size={10} /> {e.author}
              </span>
              <span className="muted" style={{ fontSize: 10.5 }}>{ago(e.created_at)}</span>
            </div>
            <div className="jbackref-body">
              <JournalMarkdown body={e.body} mentions={e.mentions} onSelect={onSelectMention} />
            </div>
          </div>
        ))}
      </div>
    </>
  );
}
