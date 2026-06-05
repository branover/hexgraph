import { useEffect, useState } from "react";
import { Observation, api } from "../api";
import { Icon } from "./Icon";
import { RawResultModal } from "./ToolResults";

const human = (s: string) => String(s || "").replace(/_/g, " ");

// "Derived from these tool results" (Phase O, design §5.6): a read-only provenance link
// on a node/finding. `ids` are the observation ids stored on the entity's
// `attrs.provenance` — the tool calls that produced or enriched it. Each row opens the
// raw CAS payload. Renders nothing when there's no provenance, so it's safe to mount
// unconditionally on any detail view.
export default function Provenance({ ids }: { ids?: string[] }) {
  const [rows, setRows] = useState<Record<string, Observation | null>>({});
  const [open, setOpen] = useState<string | null>(null);
  const list = (ids || []).filter(Boolean);

  useEffect(() => {
    let live = true;
    setRows({});
    // Fetch each referenced observation's metadata for a readable label. A missing /
    // pruned observation resolves to null and is shown as an unavailable stub.
    Promise.all(list.map((id) =>
      api.observation(id).then((o) => [id, o] as const).catch(() => [id, null] as const)
    )).then((pairs) => { if (live) setRows(Object.fromEntries(pairs)); });
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [list.join(",")]);

  if (list.length === 0) return null;
  return (
    <>
      <div className="sec">Derived from these tool results</div>
      <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
        {list.map((id) => {
          const o = rows[id];
          if (o === null) {
            return <div key={id} className="muted" style={{ fontSize: 11 }}><code>{id.slice(0, 8)}</code> · unavailable</div>;
          }
          return (
            <button key={id} className="toolresult" onClick={() => setOpen(id)} title="View the raw tool result this was derived from">
              <div className="tr-row1">
                <Icon name="task" size={12} />
                {o ? <>
                  <span className="tag" style={{ textTransform: "none" }}>{human(o.result_kind)}</span>
                  <code className="tr-tool">{o.tool}</code>
                </> : <span className="muted" style={{ fontSize: 11 }}>loading…</span>}
              </div>
              {o?.summary && <div className="tr-summary muted">{o.summary}</div>}
            </button>
          );
        })}
      </div>
      {open && <RawResultModal obsId={open} onClose={() => setOpen(null)} />}
    </>
  );
}
