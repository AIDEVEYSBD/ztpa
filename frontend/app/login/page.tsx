import { LoginForm } from "@/components/auth/LoginForm";

export default function LoginPage({ searchParams }: { searchParams: { reset?: string } }) {
  return <LoginForm reset={searchParams?.reset === "1"} />;
}
