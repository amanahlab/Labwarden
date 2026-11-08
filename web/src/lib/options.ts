import { LuBox, LuCloud, LuMonitor, LuServer } from "react-icons/lu"

export const STATUS_OPTIONS: [string, string][] = [
  ["active", "Open + acknowledged"],
  ["open", "Open"],
  ["acknowledged", "Acknowledged"],
  ["ignored", "Ignored"],
  ["false_positive", "False positive"],
  ["all", "All statuses"],
]

export const FIX_OPTIONS: [string, string][] = [
  ["fixed", "Fix available"],
  ["not-fixed", "No fix"],
  ["wont-fix", "Won't fix"],
  ["unknown", "Unknown"],
]

export const KIND_ICON: Record<string, typeof LuServer> = { vm: LuMonitor, docker: LuBox, central: LuCloud, host: LuServer }
export const KIND_LABEL: Record<string, string> = { vm: "VM", docker: "Docker", central: "Registry (central)", host: "Host" }
