import { Landing } from "@/components/Landing";

// Public marketing landing (auth gating in auth.config makes "/" public).
export default function Page() {
  return <Landing />;
}
