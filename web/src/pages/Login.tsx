import { useState } from "react"
import { useQueryClient } from "@tanstack/react-query"
import { Alert, Box, Button, Card, Center, Field, Heading, Input, Stack, Text } from "@chakra-ui/react"
import { api, ApiError } from "@/lib/api"
import { BrandSymbol } from "@/components/Brand"

export function LoginPage() {
  const qc = useQueryClient()
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError("")
    try {
      await api.post("/auth/login", { password })
      await qc.invalidateQueries()
    } catch (err) {
      setError(err instanceof ApiError && err.status === 401 ? "Incorrect password" : (err as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Center minH="100vh" p="4" bg="canvas">
      <Card.Root w="full" maxW="sm" variant="elevated" bg="surface">
        <Card.Body>
          <form onSubmit={submit}>
            <Stack gap="6">
              <Stack gap="3" align="center" textAlign="center">
                <BrandSymbol size={56} />
                <Box>
                  <Heading size="lg">Sign in to LabWarden</Heading>
                  <Text color="fg.muted" textStyle="sm">
                    Vulnerability dashboard for your homelab
                  </Text>
                </Box>
              </Stack>
              {error && (
                <Alert.Root status="error" size="sm">
                  <Alert.Indicator />
                  <Alert.Title>{error}</Alert.Title>
                </Alert.Root>
              )}
              <Field.Root required>
                <Field.Label>Admin password</Field.Label>
                <Input type="password" autoFocus autoComplete="current-password" value={password} onChange={(e) => setPassword(e.currentTarget.value)} />
              </Field.Root>
              <Button type="submit" loading={busy} disabled={!password}>
                Sign in
              </Button>
            </Stack>
          </form>
        </Card.Body>
      </Card.Root>
    </Center>
  )
}
