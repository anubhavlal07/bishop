"use client";

import { useEffect, useMemo } from "react";
import ReactFlow, {
  Background,
  Controls,
  type Edge,
  Handle,
  type Node,
  type NodeProps,
  Position,
  useEdgesState,
  useNodesState,
} from "reactflow";

import type { RunEvent } from "@/lib/types";

type NodeState = "idle" | "active" | "done" | "waiting" | "failed";

interface BishopNodeData {
  label: string;
  detail?: string;
  state: NodeState;
  kind: "stage" | "investigator" | "gate";
}

const STATE_COLOUR: Record<NodeState, string> = {
  idle: "var(--edge)",
  active: "#58a6ff",
  done: "#4ec9a5",
  waiting: "#e3b341",
  failed: "#f2555a",
};

function BishopNode({ data }: NodeProps<BishopNodeData>) {
  const colour = STATE_COLOUR[data.state];
  const isGate = data.kind === "gate";
  return (
    <div
      className={`rounded-md px-3 py-2 text-xs ${data.state === "active" ? "node-active" : ""}`}
      style={{
        background: "var(--panel)",
        border: `${isGate ? 2 : 1}px ${isGate ? "double" : "solid"} ${colour}`,
        minWidth: 150,
        opacity: data.state === "idle" ? 0.45 : 1,
      }}
    >
      <Handle
        type="target"
        position={Position.Left}
        style={{ background: colour }}
      />
      <div
        className="font-medium"
        style={{ color: data.state === "idle" ? undefined : colour }}
      >
        {data.label}
      </div>
      {data.detail && (
        <div className="muted mt-0.5 text-[10px]">{data.detail}</div>
      )}
      <Handle
        type="source"
        position={Position.Right}
        style={{ background: colour }}
      />
    </div>
  );
}

const nodeTypes = { bishop: BishopNode };

const INVESTIGATORS = [
  "identity",
  "endpoint",
  "network",
  "threatintel",
  "context",
] as const;

function baseNodes(): Node<BishopNodeData>[] {
  const nodes: Node<BishopNodeData>[] = [
    {
      id: "ingest",
      position: { x: 0, y: 180 },
      data: {
        label: "ingest",
        detail: "quarantine",
        state: "idle",
        kind: "stage",
      },
      type: "bishop",
    },
    {
      id: "triage_supervisor",
      position: { x: 190, y: 180 },
      data: { label: "triage_supervisor", state: "idle", kind: "stage" },
      type: "bishop",
    },
  ];
  INVESTIGATORS.forEach((surface, index) => {
    nodes.push({
      id: `investigator:${surface}`,
      position: { x: 410, y: index * 76 },
      data: {
        label: `${surface}_investigator`,
        state: "idle",
        kind: "investigator",
      },
      type: "bishop",
    });
  });
  nodes.push(
    {
      id: "synthesis",
      position: { x: 640, y: 145 },
      data: {
        label: "synthesis",
        detail: "ATT&CK mapping",
        state: "idle",
        kind: "stage",
      },
      type: "bishop",
    },
    {
      id: "adversarial_critic",
      position: { x: 640, y: 225 },
      data: { label: "adversarial_critic", state: "idle", kind: "stage" },
      type: "bishop",
    },
    {
      id: "response_planner",
      position: { x: 860, y: 145 },
      data: { label: "response_planner", state: "idle", kind: "stage" },
      type: "bishop",
    },
    {
      id: "response_gate",
      position: { x: 860, y: 225 },
      data: {
        label: "response_gate",
        detail: "human decides",
        state: "idle",
        kind: "gate",
      },
      type: "bishop",
    },
    {
      id: "response_execute",
      position: { x: 1080, y: 185 },
      data: {
        label: "response_execute",
        detail: "mocked",
        state: "idle",
        kind: "stage",
      },
      type: "bishop",
    },
    {
      id: "report",
      position: { x: 1080, y: 105 },
      data: { label: "report", state: "idle", kind: "stage" },
      type: "bishop",
    },
  );
  return nodes;
}

function baseEdges(): Edge[] {
  const edges: Edge[] = [
    { id: "e1", source: "ingest", target: "triage_supervisor" },
  ];
  for (const surface of INVESTIGATORS) {
    edges.push({
      id: `e-in-${surface}`,
      source: "triage_supervisor",
      target: `investigator:${surface}`,
    });
    edges.push({
      id: `e-out-${surface}`,
      source: `investigator:${surface}`,
      target: "synthesis",
    });
  }
  edges.push(
    { id: "e2", source: "synthesis", target: "adversarial_critic" },
    { id: "e3", source: "adversarial_critic", target: "response_planner" },
    { id: "e4", source: "response_planner", target: "response_gate" },
    { id: "e5", source: "response_gate", target: "response_execute" },
    { id: "e6", source: "response_execute", target: "report" },
  );
  return edges.map((edge) => ({
    ...edge,
    animated: false,
    style: { stroke: "var(--edge)" },
  }));
}

function statesFor(
  events: RunEvent[],
): Record<string, { state: NodeState; detail?: string }> {
  const out: Record<string, { state: NodeState; detail?: string }> = {};
  const set = (id: string, state: NodeState, detail?: string) => {
    out[id] = { state, detail: detail ?? out[id]?.detail };
  };

  for (const event of events) {
    switch (event.kind) {
      case "started":
      case "continued":
        set("ingest", "active");
        break;
      case "ingested":
        set(
          "ingest",
          "done",
          `${String(event.quarantined_fields ?? 0)} fields quarantined`,
        );
        break;
      case "injection_detected":
        set("ingest", "done", "injection found");
        break;
      case "dispatched": {
        set("triage_supervisor", "done");
        const surfaces = (event.surfaces as string[]) ?? [];
        for (const surface of surfaces)
          set(`investigator:${surface}`, "active");
        break;
      }
      case "detectors_ran": {
        const surface = String(event.surface);
        set(
          `investigator:${surface}`,
          "active",
          `${String(event.fired ?? 0)}/${String(event.total ?? 0)} fired`,
        );
        break;
      }
      case "investigator_reported": {
        const surface = String(event.surface);
        set(
          `investigator:${surface}`,
          "done",
          `${String(event.findings ?? 0)} findings · ${String(event.duration_ms ?? 0)}ms`,
        );
        set("synthesis", "active");
        break;
      }
      case "verdict":
        set("synthesis", "done", String(event.label ?? ""));
        set("adversarial_critic", "active");
        break;
      case "critique":
        set(
          "adversarial_critic",
          "done",
          `${String(event.arguments ?? 0)} counter-arguments`,
        );
        set("response_planner", "active");
        break;
      case "response_planned":
        set(
          "response_planner",
          "done",
          `${String(event.actions ?? 0)} actions proposed`,
        );
        break;
      case "approval_requested":
      case "awaiting_approval":
        set("response_gate", "waiting", "awaiting a human");
        break;
      case "human_decided":
        set("response_gate", "done", String(event.decision ?? ""));
        set("response_execute", "active");
        break;
      case "action_executed":
      case "action_refused":
        set("response_execute", "active");
        break;
      case "completed":
        set("response_execute", "done");
        set("report", "done");
        break;
      case "failed":
        set("report", "failed", String(event.error ?? "failed"));
        break;
    }
  }
  return out;
}

export function Topology({ events }: { events: RunEvent[] }) {
  const [nodes, setNodes, onNodesChange] =
    useNodesState<BishopNodeData>(baseNodes());
  const [edges, setEdges, onEdgesChange] = useEdgesState(baseEdges());

  const states = useMemo(() => statesFor(events), [events]);

  useEffect(() => {
    setNodes((current) =>
      current.map((node) => {
        const next = states[node.id];
        if (!next) return node;
        return {
          ...node,
          data: {
            ...node.data,
            state: next.state,
            detail: next.detail ?? node.data.detail,
          },
        };
      }),
    );
    setEdges((current) =>
      current.map((edge) => {
        const sourceState = states[edge.source]?.state;
        const targetState = states[edge.target]?.state;
        const live =
          sourceState === "done" &&
          (targetState === "active" || targetState === "waiting");
        return {
          ...edge,
          animated: live,
          style: {
            stroke: sourceState === "done" ? "#4ec9a5" : "var(--edge)",
            opacity: sourceState ? 1 : 0.4,
          },
        };
      }),
    );
  }, [states, setNodes, setEdges]);

  return (
    <div style={{ height: 420 }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        fitView
        proOptions={{ hideAttribution: true }}
        nodesDraggable={false}
        nodesConnectable={false}
      >
        <Background color="var(--edge)" gap={20} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
