import { HStack } from "@chakra-ui/react"
import { LuServer } from "react-icons/lu"
import { KIND_ICON, KIND_LABEL } from "@/lib/options"

export function KindTag({ kind }: { kind: string }) {
  const Icon = KIND_ICON[kind] ?? LuServer
  return (
    <HStack gap="1.5" color="fg.muted" textStyle="sm" whiteSpace="nowrap">
      <Icon size={14} />
      {KIND_LABEL[kind] ?? kind}
    </HStack>
  )
}
