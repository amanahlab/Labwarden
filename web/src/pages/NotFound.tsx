import { Button } from "@chakra-ui/react"
import { Link } from "react-router"
import { LuCompass } from "react-icons/lu"
import { Empty } from "@/components/common"

export function NotFoundPage() {
  return (
    <Empty
      icon={<LuCompass />}
      title="Page not found"
      description="The page you were looking for does not exist."
      action={
        <Button asChild size="sm" variant="outline">
          <Link to="/">Back to overview</Link>
        </Button>
      }
    />
  )
}
