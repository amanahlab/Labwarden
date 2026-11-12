import type { ReactNode } from "react"
import { Box, CloseButton, Drawer, HStack, Portal, Stack } from "@chakra-ui/react"

// A panel that floats in from the right for one task with a form: adding a
// host, editing one, triage. It is the only surface with a shadow. Confirming
// something destructive stays a centered alert dialog.
//
// The children are mounted when the sheet opens and dropped once it has
// closed, so form state inside starts fresh every time. They render a
// SheetBody and, under it, a SheetFooter that stays in view.
export function Sheet(props: { open: boolean; onClose: () => void; title: ReactNode; description?: ReactNode; size?: "sm" | "md" | "lg"; children: ReactNode }) {
  return (
    <Drawer.Root open={props.open} onOpenChange={(e) => !e.open && props.onClose()} placement="end" size={props.size ?? "md"}>
      <Portal>
        <Drawer.Backdrop />
        {/* The padding is the gap to the window edge; a phone gets the full width. */}
        <Drawer.Positioner padding={{ base: "0", md: "3" }}>
          <Drawer.Content bg="surface" boxShadow="overlay" rounded={{ base: "none", md: "sheet" }}>
            <Drawer.Header pe="14">
              <Stack gap="1">
                <Drawer.Title>{props.title}</Drawer.Title>
                {props.description && (
                  <Drawer.Description textStyle="sm" color="fg.muted">
                    {props.description}
                  </Drawer.Description>
                )}
              </Stack>
            </Drawer.Header>
            {props.children}
            <Drawer.CloseTrigger asChild>
              <CloseButton size="sm" />
            </Drawer.CloseTrigger>
          </Drawer.Content>
        </Drawer.Positioner>
      </Portal>
    </Drawer.Root>
  )
}

export function SheetBody(props: Drawer.BodyProps) {
  return <Drawer.Body {...props} />
}

// What will happen on the left, the buttons that do it on the right.
export function SheetFooter({ summary, children }: { summary?: ReactNode; children: ReactNode }) {
  return (
    <Drawer.Footer borderTopWidth="1px" justifyContent="space-between" gap="3">
      <Box textStyle="sm" color="fg.muted" minW="0">
        {summary}
      </Box>
      <HStack gap="2" flexShrink={0}>
        {children}
      </HStack>
    </Drawer.Footer>
  )
}
