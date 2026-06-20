import { MagicSignIn } from "@/components/auth/MagicSignIn";

export default function MagicPage({ searchParams }: { searchParams: { token?: string } }) {
  return <MagicSignIn token={searchParams?.token ?? ""} />;
}
