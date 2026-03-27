import { ReactNode } from 'react';
import { ExamSecureShell } from '@/components/student/StudentShell';

export default function ExamLayout({ children }: { children: ReactNode }) {
  return (
    <ExamSecureShell>
      {children}
    </ExamSecureShell>
  );
}
