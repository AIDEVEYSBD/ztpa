import { ResetForm } from "@/components/auth/ResetForm";

export default function ResetPage({ searchParams }: { searchParams: { token?: string } }) {
  return <ResetForm token={searchParams?.token ?? ""} />;
}
