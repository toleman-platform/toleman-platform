# Toleman Platform - Frontend

The Next.js 16 (App Router + Turbopack) dashboard for the **Toleman Security & Vulnerability Platform**.

---

## 📚 Documentation & System Guides

- **[Design System Manual](DESIGN_SYSTEM.md)**: Design tokens, dual-palette colors, scalable typography scale, spatial grid rules of thumb, and WCAG AA contrast rules.
- **[Component Architecture Guide](COMPONENTS.md)**: Layered component catalog (L1 Primitives, L2 Domain Patterns, L3 Page Views), async state patterns, and boundary lint rules.
- **Live Design Gallery**: Access `/design-system` on the running dev server for interactive token specimens.

---

## 🛠️ Getting Started

### Prerequisites
- Node.js 20+
- `npm`

### Installation & Development

```bash
# Install dependencies
npm install

# Run development server with Turbopack
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) to view the dashboard.

---

## 🧪 Testing & Verification

```bash
# Run unit & component tests (Vitest)
npm test

# Run ESLint checks
npm run lint

# Verify client/server component boundary rules
npm run lint:boundary

# Production build
npm run build
```
