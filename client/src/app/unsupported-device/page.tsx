export default function UnsupportedDevicePage() {
  return (
    <main
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '24px',
        background: 'linear-gradient(180deg, #F8FAFC 0%, #EEF6FB 100%)',
      }}
    >
      <div
        style={{
          width: '100%',
          maxWidth: '640px',
          background: '#FFFFFF',
          border: '1px solid #E2E8F0',
          borderRadius: '20px',
          boxShadow: '0 20px 60px rgba(15, 23, 42, 0.08)',
          padding: '32px',
          textAlign: 'center',
        }}
      >
        <div
          style={{
            width: '72px',
            height: '72px',
            margin: '0 auto 20px',
            borderRadius: '18px',
            background: 'linear-gradient(135deg, #22577A 0%, #38A3A5 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#FFFFFF',
            fontSize: '30px',
            fontWeight: 700,
          }}
        >
          !
        </div>

        <h1
          style={{
            margin: '0 0 12px',
            color: '#0F172A',
            fontSize: '32px',
            lineHeight: 1.15,
            fontWeight: 800,
            letterSpacing: '-0.03em',
          }}
        >
          Device Not Supported
        </h1>

        <p
          style={{
            margin: '0 0 24px',
            color: '#475569',
            fontSize: '16px',
            lineHeight: 1.7,
          }}
        >
          This application is available only on desktop or laptop computers.
          Mobile phones, tablets, and iPads are not supported for access or exam
          participation.
        </p>

        <div
          style={{
            borderRadius: '14px',
            background: '#F8FAFC',
            border: '1px solid #E2E8F0',
            padding: '18px 20px',
            color: '#64748B',
            fontSize: '14px',
            lineHeight: 1.7,
          }}
        >
          Please reopen this application on a desktop or laptop with a supported
          browser to continue.
        </div>
      </div>
    </main>
  );
}
