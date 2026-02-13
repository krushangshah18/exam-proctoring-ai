import RoleGuard from '@/components/auth/role-guard';

export default function AdminDashboard() {
  return (
    <RoleGuard allowedRoles={['ADMIN']}>
      <div className="p-8">
        <h1 className="text-3xl font-bold mb-4">Exam Admin Dashboard</h1>
        <p>Welcome to the Exam Admin Dashboard. Here you can manage exams and view reports.</p>
      </div>
    </RoleGuard>
  );
}
