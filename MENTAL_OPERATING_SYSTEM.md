# HỆ TƯ DUY CỐT LÕI (MENTAL OPERATING SYSTEM)
## Phiên bản Tối ưu: Từ Tư Duy → Thực Hành → Kết Quả

---

## MỤC LỤC

1. [Nguyên Lý Nền Tảng](#i-nguyên-lý-nền-tảng)
2. [Quy Trình Tư Duy 5 Bước](#ii-quy-trình-tư-duy-5-bước)
3. [Decision Trees Thực Hành](#iii-decision-trees-thực-hành)
4. [Checklist Hành Động](#iv-checklist-hành-động)
5. [Ví Dụ Thực Tế](#v-ví-dụ-thực-tế)
6. [Đo Lường Kết Quả](#vi-đo-lường-kết-quả)

---

## I. NGUYÊN LÝ NỀN TẢNG

### 1.1 Công Thức Cốt Lõi

```
EXPLOIT = Execution Primitive + User-Controlled Data + Reachable Path
```

**Ba câu hỏi BẮT BUỘC trước mọi phân tích:**

| # | Câu hỏi | Nếu KHÔNG → |
|---|---------|-------------|
| 1 | Code chạy ở đâu? (Build-time/Runtime/Edge/Node) | DỪNG - Không hiểu target |
| 2 | Ai kiểm soát data? (User/Server/Config) | DỪNG - Không có attack vector |
| 3 | Execution boundary nằm ở đâu? | DỪNG - Không có primitive |

### 1.2 Tư Duy DENY-FIRST

```
┌─────────────────────────────────────────────────────────┐
│  ❌ SAI: "Làm sao exploit được?"                        │
│  ✅ ĐÚNG: "Có lý do gì khiến KHÔNG exploit được?"       │
└─────────────────────────────────────────────────────────┘
```

**Quy tắc vàng:**
> Nếu bạn không thể DENY được giả thuyết exploit → Mới xứng đáng viết payload

### 1.3 CVE ≠ Exploit

```
CVE (Framework Bug)  ─╲
                       ╲
                        ╳─→ CẦN KIỂM CHỨNG
                       ╱
App (Thực tế)        ─╱
```

**Công thức:**
```
CVE = Hypothesis (Giả thuyết)
App = Reality (Thực tế cần kiểm chứng)
Exploit = CVE ∩ App ∩ Execution Primitive
```

---

## II. QUY TRÌNH TƯ DUY 5 BƯỚC

### Bước 1: SIGNAL DETECTION (Thu thập tín hiệu)

```
INPUT: CVE / Bug Report / Code Pattern
   │
   ▼
┌──────────────────────────────────┐
│  PHÂN LOẠI SIGNAL                │
│  ├─ CVE công bố                  │
│  ├─ Code pattern đáng ngờ        │
│  ├─ Configuration sai            │
│  └─ Logic flaw                   │
└──────────────────────────────────┘
   │
   ▼
OUTPUT: Signal Type + Severity Estimate
```

**Checklist Bước 1:**
- [ ] Signal từ nguồn nào? (CVE DB / Code review / Fuzzing)
- [ ] Framework/Library nào bị ảnh hưởng?
- [ ] Version range nào?
- [ ] Điều kiện kích hoạt là gì?

---

### Bước 2: MECHANISM ANALYSIS (Phân tích cơ chế)

```
INPUT: Signal đã phân loại
   │
   ▼
┌──────────────────────────────────┐
│  HIỂU CƠ CHẾ Ở FRAMEWORK-LEVEL  │
│                                  │
│  Câu hỏi cần trả lời:            │
│  1. Bug xảy ra ở layer nào?      │
│  2. Điều kiện trigger là gì?     │
│  3. Impact lý thuyết là gì?      │
└──────────────────────────────────┘
   │
   ▼
OUTPUT: Mechanism Understanding Document
```

**Layer Classification:**

| Layer | Ví dụ | Bypass được | KHÔNG bypass được |
|-------|-------|-------------|-------------------|
| Routing | URL matching, redirect | Auth gate | Code logic |
| UI | Page render, CSR | Visual | API / DB |
| Middleware | Pre-check, headers | Validation | Runtime execution |
| Runtime | Code execution | - | Sandbox |

**Template Mechanism Doc:**
```markdown
## Mechanism Analysis: [CVE-XXXX-XXXXX]

**Layer:** [Routing/UI/Middleware/Runtime]
**Trigger:** [Điều kiện kích hoạt]
**Theoretical Impact:** [RCE/Auth Bypass/Info Leak/...]
**Framework Version:** [x.x.x - y.y.y]
```

---

### Bước 3: TARGET ARCHITECTURE MAPPING (Mapping kiến trúc)

```
INPUT: Target Application
   │
   ▼
┌──────────────────────────────────────────────────────┐
│  VẼ SƠ ĐỒ KIẾN TRÚC                                  │
│                                                      │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐          │
│  │  Auth   │───▶│  Logic  │───▶│  Data   │          │
│  └─────────┘    └─────────┘    └─────────┘          │
│       │              │              │                │
│       ▼              ▼              ▼                │
│  [Middleware]   [API Route]   [Database]            │
│                                                      │
└──────────────────────────────────────────────────────┘
   │
   ▼
OUTPUT: Architecture Diagram + Entry Points
```

**4 Components BẮT BUỘC phải identify:**

```
┌────────────────────────────────────────────────┐
│ 1. AUTH: Xác thực ở đâu?                       │
│    → middleware.ts? API route? External?       │
│                                                │
│ 2. LOGIC: Business logic ở đâu?                │
│    → Server Actions? API handlers? RSC?        │
│                                                │
│ 3. DATA: Data fetch ở đâu?                     │
│    → getServerSideProps? Server Components?    │
│                                                │
│ 4. EXECUTION: Code execution ở đâu?            │
│    → eval? Dynamic import? Template render?    │
└────────────────────────────────────────────────┘
```

**Architecture Template:**
```
TARGET: [App Name]
STACK: [Next.js 14 / React 18 / Node 20]

AUTH LAYER:
  - Location: [file path]
  - Type: [JWT/Session/OAuth]
  - Bypass potential: [Yes/No/Partial]

LOGIC LAYER:
  - Server Actions: [Yes/No] → [paths]
  - API Routes: [Yes/No] → [paths]
  - Middleware: [Yes/No] → [paths]

DATA LAYER:
  - DB: [Type]
  - ORM: [Prisma/Drizzle/Raw]
  - User-controlled queries: [Yes/No]

EXECUTION LAYER:
  - Dynamic imports: [Yes/No]
  - Template engines: [Yes/No]
  - eval/Function: [Yes/No]
```

---

### Bước 4: EXECUTION PRIMITIVE CHECK (Kiểm tra primitive)

```
INPUT: Architecture Map + Mechanism Understanding
   │
   ▼
┌──────────────────────────────────────────────────────┐
│  EXECUTION PRIMITIVE TREE                            │
│                                                      │
│  User Input                                          │
│      │                                               │
│      ▼                                               │
│  ┌─────────────────────────────────────┐            │
│  │ CHẶN BỞI?                           │            │
│  │ □ Bundle (webpack/turbopack)        │            │
│  │ □ Manifest (route manifest)         │            │
│  │ □ Allowlist (config whitelist)      │            │
│  │ □ Cache (static generation)         │            │
│  │ □ Compile-time freeze               │            │
│  │ □ Sandbox (VM/Container)            │            │
│  └─────────────────────────────────────┘            │
│      │                                               │
│      ▼                                               │
│  Evaluation Boundary ←── Input có chạm được?        │
│      │                                               │
│      ▼                                               │
│  Side Effect (RCE/Data Leak/...)                    │
│                                                      │
└──────────────────────────────────────────────────────┘
   │
   ▼
OUTPUT: [EXPLOITABLE] hoặc [NOT EXPLOITABLE] + Reason
```

**Decision Matrix:**

```
┌─────────────────────────────────────────────────────────────┐
│ Input reaches execution boundary?                           │
│     │                                                       │
│     ├─ NO ──────────────────────────────▶ NOT EXPLOITABLE  │
│     │                                                       │
│     └─ YES                                                  │
│          │                                                  │
│          ▼                                                  │
│     Execution primitive exists?                             │
│          │                                                  │
│          ├─ NO ─────────────────────────▶ NOT EXPLOITABLE  │
│          │                                                  │
│          └─ YES                                             │
│               │                                             │
│               ▼                                             │
│          Barriers can be bypassed?                          │
│               │                                             │
│               ├─ NO ────────────────────▶ NOT EXPLOITABLE  │
│               │                                             │
│               └─ YES ───────────────────▶ EXPLOITABLE ✓    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

### Bước 5: EXPLOIT DEVELOPMENT (Chỉ khi EXPLOITABLE)

```
INPUT: Confirmed Exploitable Target
   │
   ▼
┌──────────────────────────────────────────────────────┐
│  PAYLOAD DEVELOPMENT                                 │
│                                                      │
│  1. Minimal PoC (chứng minh concept)                │
│     └─▶ Trigger bug với input đơn giản nhất        │
│                                                      │
│  2. Weaponization (nếu cần)                         │
│     └─▶ Bypass WAF/filters                          │
│     └─▶ Chain với bugs khác                         │
│                                                      │
│  3. Documentation                                    │
│     └─▶ Steps to reproduce                          │
│     └─▶ Impact assessment                           │
│     └─▶ Remediation                                 │
│                                                      │
└──────────────────────────────────────────────────────┘
   │
   ▼
OUTPUT: Working Exploit + Report
```

---

## III. DECISION TREES THỰC HÀNH

### 3.1 CVE Triage Tree

```
                    CVE Mới
                       │
                       ▼
        ┌──────────────────────────┐
        │ Target dùng framework    │
        │ bị ảnh hưởng?            │
        └──────────────────────────┘
                │           │
              YES          NO ───────▶ SKIP
                │
                ▼
        ┌──────────────────────────┐
        │ Version trong range      │
        │ vulnerable?              │
        └──────────────────────────┘
                │           │
              YES          NO ───────▶ SKIP
                │
                ▼
        ┌──────────────────────────┐
        │ Vulnerable code path     │
        │ có được sử dụng?         │
        └──────────────────────────┘
                │           │
              YES          NO ───────▶ SKIP
                │
                ▼
        ┌──────────────────────────┐
        │ User input có reach      │
        │ được code path?          │
        └──────────────────────────┘
                │           │
              YES          NO ───────▶ SKIP
                │
                ▼
           INVESTIGATE
```

### 3.2 Next.js Specific Tree

```
              Next.js Target
                    │
                    ▼
        ┌─────────────────────┐
        │ Middleware exists?  │
        └─────────────────────┘
              │         │
            YES        NO
              │         │
              ▼         │
    ┌─────────────────┐ │
    │ Auth logic in   │ │
    │ middleware?     │ │
    └─────────────────┘ │
        │       │       │
      YES      NO       │
        │       │       │
        ▼       ▼       ▼
    CHECK    SKIP    CHECK
    CVE-2025  MW     OTHER
    -29927    PATH   VECTORS
        │
        ▼
    ┌─────────────────────────┐
    │ Protected routes via    │
    │ middleware only?        │
    │ (No API-level auth)     │
    └─────────────────────────┘
        │           │
      YES          NO ─────────▶ LIMITED IMPACT
        │
        ▼
    ┌─────────────────────────┐
    │ Sensitive data/actions  │
    │ behind those routes?    │
    └─────────────────────────┘
        │           │
      YES          NO ─────────▶ LOW IMPACT
        │
        ▼
    HIGH IMPACT - PROCEED
```

### 3.3 Execution Primitive Detection Tree

```
              Analyze Codebase
                    │
         ┌─────────┴─────────┐
         ▼                   ▼
    Server-Side         Client-Side
         │                   │
    ┌────┴────┐         (Limited scope)
    ▼         ▼
  Direct   Indirect
  Exec     Exec
    │         │
    ▼         ▼
┌───────┐ ┌───────────┐
│ eval  │ │ Dynamic   │
│ Func- │ │ import()  │
│ tion()│ │ require() │
│ vm.*  │ │ Template  │
│ exec  │ │ engines   │
│ spawn │ │ Deserial- │
└───────┘ │ ization   │
          └───────────┘
              │
              ▼
    ┌─────────────────────┐
    │ User data reaches   │
    │ these primitives?   │
    └─────────────────────┘
        │           │
      YES          NO
        │           │
        ▼           ▼
    CRITICAL    NOT VULN
```

---

## IV. CHECKLIST HÀNH ĐỘNG

### 4.1 Pre-Analysis Checklist

```markdown
## Trước khi phân tích CVE/Target

- [ ] Đã đọc CVE description đầy đủ
- [ ] Đã xác định framework + version
- [ ] Đã xác định affected component
- [ ] Đã hiểu theoretical impact
- [ ] Đã setup lab environment (nếu cần)
```

### 4.2 Architecture Mapping Checklist

```markdown
## Mapping target architecture

- [ ] Identify tech stack (framework, runtime, DB)
- [ ] Locate authentication code
- [ ] Locate authorization code
- [ ] Map all user input entry points
- [ ] Identify data flow paths
- [ ] Find execution primitives (eval, import, template)
- [ ] Document all middleware/interceptors
- [ ] Check for security configurations
```

### 4.3 Exploitability Checklist

```markdown
## Xác định exploitability

- [ ] User input có đến được vulnerable code?
- [ ] Có barrier nào chặn không?
  - [ ] WAF
  - [ ] Input validation
  - [ ] Allowlist
  - [ ] Compile-time restrictions
- [ ] Execution primitive có tồn tại?
- [ ] Side effect có impact không?
- [ ] Đã thử DENY hypothesis chưa?
```

### 4.4 DENY Hypothesis Checklist

```markdown
## Checklist bác bỏ giả thuyết exploit

Đã kiểm tra các lý do KHÔNG exploitable:

- [ ] Input bị sanitize trước khi đến vulnerable code
- [ ] Vulnerable code không được sử dụng trong app
- [ ] Route/path không accessible từ outside
- [ ] Execution primitive không tồn tại
- [ ] Barrier không thể bypass
- [ ] Version đã được patch
- [ ] Configuration disable vulnerable feature
```

---

## V. VÍ DỤ THỰC TẾ

### Ví dụ 1: CVE-2025-29927 (Next.js Middleware Bypass)

**Bước 1: Signal Detection**
```
Signal: CVE-2025-29927
Framework: Next.js
Version: < 15.2.3, < 14.2.25, < 13.5.9
Type: Authorization Bypass
```

**Bước 2: Mechanism Analysis**
```
Layer: ROUTING (không phải Runtime)
Trigger: x-middleware-subrequest header
Impact lý thuyết: Bypass middleware checks
```

**Bước 3: Target Mapping**
```
Target: E-commerce App
Auth: middleware.ts (checks JWT)
Protected routes: /admin/*, /api/admin/*
API routes: Has own auth check? → KIỂM TRA
```

**Bước 4: Execution Primitive Check**
```
Q: Bypass middleware → có execution primitive?
A: KHÔNG - Middleware bypass chỉ ở routing layer

Q: API routes có auth riêng không?
A: CÓ - API routes check JWT independently

→ Kết luận: LIMITED IMPACT
   Middleware bypass ≠ Full auth bypass
   Vì API có auth layer riêng
```

**Bước 5: Kết quả**
```
Status: NOT FULLY EXPLOITABLE
Reason: Target có defense-in-depth
        API layer có independent auth
Impact: Có thể access UI routes,
        KHÔNG thể thực hiện sensitive actions
```

### Ví dụ 2: SSTI trong Template Engine

**Bước 1: Signal Detection**
```
Signal: Code pattern review
Found: res.render(template, {userInput})
Type: Potential SSTI
```

**Bước 2: Mechanism Analysis**
```
Layer: RUNTIME (execution primitive!)
Trigger: User-controlled template variable
Impact lý thuyết: RCE
```

**Bước 3: Target Mapping**
```
Template engine: EJS
User input: query parameter 'name'
Flow: req.query.name → template variable
```

**Bước 4: Execution Primitive Check**
```
Q: User input reaches template engine?
A: CÓ - trực tiếp qua query param

Q: Có barrier nào?
A: KHÔNG - input không được sanitize

Q: Template engine có execution primitive?
A: CÓ - EJS allows code execution

→ Kết luận: EXPLOITABLE
```

**Bước 5: Exploit Development**
```
Minimal PoC: /?name=<%= process.env %>
Weaponized: /?name=<%= require('child_process').execSync('id') %>
```

---

## VI. ĐO LƯỜNG KẾT QUẢ

### 6.1 Metrics Theo Dõi

| Metric | Mô tả | Target |
|--------|-------|--------|
| True Positive Rate | Exploit đúng / Tổng exploit báo cáo | > 90% |
| False Positive Rate | Exploit sai / Tổng exploit báo cáo | < 10% |
| Analysis Depth | Đã hoàn thành đủ 5 bước? | 100% |
| DENY Attempts | Số lần thử bác bỏ trước khi confirm | >= 3 |
| Time-to-Decision | Thời gian từ signal đến kết luận | Giảm dần |

### 6.2 Self-Assessment Questions

Sau mỗi phân tích, tự hỏi:

```
1. Tôi có skip bước nào không?
   → Nếu có, quay lại làm đủ

2. Tôi có thử DENY đủ chưa?
   → Nếu < 3 lần, thử thêm

3. Kết luận có evidence không?
   → Nếu không, chưa đủ để kết luận

4. Tôi có bị bias không?
   → Muốn nó exploit quá? Dừng lại, nghỉ, làm lại

5. Người khác có thể reproduce không?
   → Nếu không, document chưa đủ
```

### 6.3 Training Loop

```
┌─────────────────────────────────────────────────────────────┐
│                    TRAINING LOOP                            │
│                                                             │
│  1. Nhận CVE/Target mới                                     │
│          │                                                  │
│          ▼                                                  │
│  2. Viết DENY document trước                                │
│     "Tại sao exploit CÓ THỂ KHÔNG tồn tại?"                │
│          │                                                  │
│          ▼                                                  │
│  3. Không tìm được lý do deny?                              │
│     │                                                       │
│     ├─ TÌM ĐƯỢC ──────▶ Kết luận NOT EXPLOITABLE           │
│     │                         │                             │
│     │                         ▼                             │
│     │                   Document lý do                      │
│     │                         │                             │
│     └─ KHÔNG TÌM ĐƯỢC ──────┐ │                             │
│                             │ │                             │
│                             ▼ ▼                             │
│  4. Proceed to exploit ◀────┘                               │
│          │                                                  │
│          ▼                                                  │
│  5. Exploit fail?                                           │
│     │                                                       │
│     ├─ YES ─────────────▶ Quay lại bước 2                  │
│     │                     KHÔNG viết payload mới            │
│     │                                                       │
│     └─ NO ──────────────▶ Document thành công              │
│                                                             │
│  6. Review & Learn                                          │
│     - Sai ở đâu?                                            │
│     - Thiếu knowledge gì?                                   │
│     - Process nào cần improve?                              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## VII. KNOWLEDGE MAP

### 7.1 Kiến Thức BẮT BUỘC

```
┌─────────────────────────────────────────────────────────────┐
│ EXECUTION MODELS (Quan trọng nhất)                         │
│                                                             │
│  Build-time ←──────────────────────────▶ Runtime           │
│      │                                       │              │
│  Static generation              Dynamic execution          │
│  Webpack bundling               Server-side rendering      │
│  Tree shaking                   API handlers               │
│                                                             │
│  Edge ←────────────────────────────────▶ Node              │
│      │                                       │              │
│  Limited APIs                   Full Node.js APIs          │
│  V8 isolates                    Full process access        │
│                                                             │
│  RSC ←─────────────────────────────────▶ Client            │
│      │                                       │              │
│  Server-only code               Browser execution          │
│  No hydration                   Full React lifecycle       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 7.2 Data Flow Analysis

```
┌─────────────────────────────────────────────────────────────┐
│ DATA FLOW QUESTIONS                                         │
│                                                             │
│  START: User-controlled input ở đâu?                        │
│      │                                                      │
│      ▼                                                      │
│  TRACE: Data đi qua những function nào?                     │
│      │                                                      │
│      ▼                                                      │
│  CHECK: Có transformation/sanitization không?               │
│      │                                                      │
│      ▼                                                      │
│  END: Data có đến code-that-runs không?                     │
│                                                             │
│  ─────────────────────────────────────────────────────────  │
│                                                             │
│  "Code that runs" =                                         │
│    • eval() / Function()                                    │
│    • Dynamic import()                                       │
│    • Template engine render                                 │
│    • SQL query execution                                    │
│    • Command execution (exec/spawn)                         │
│    • Deserialization                                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 7.3 Kiến Thức KHÔNG Cần Ưu Tiên

```
❌ Payload obfuscation (chỉ cần khi có primitive)
❌ Exotic bypass encoding (edge cases)
❌ Fancy callback tricks (premature optimization)
❌ CVE memorization (hiểu mechanism > nhớ số)
```

---

## VIII. SCANNER DESIGN PRINCIPLES

### 8.1 Scanner Đúng vs Sai

```
❌ SCANNER SAI hỏi:
   "Target có CVE-XXXX không?"
   → Chỉ check version, không check exploitability

✅ SCANNER ĐÚNG hỏi:
   "Target có execution primitive không?"
   → Check actual code patterns
```

### 8.2 Patterns Cần Detect

```python
# Scanner should look for:

EXECUTION_PRIMITIVES = [
    # Direct execution
    r'eval\s*\(',
    r'Function\s*\(',
    r'vm\.(run|createContext)',
    r'child_process\.(exec|spawn)',

    # Indirect execution
    r'import\s*\([^)]*\+',        # Dynamic import với concat
    r'require\s*\([^)]*\+',       # Dynamic require với concat
    r'\.render\s*\([^,]+,\s*\{',  # Template render với data

    # Deserialization
    r'JSON\.parse\s*\(',
    r'serialize\s*\(',
    r'unserialize\s*\(',
]

USER_INPUT_SOURCES = [
    r'req\.(query|body|params|headers)',
    r'request\.(query|body|params|headers)',
    r'searchParams',
    r'formData',
]

# Good scanner: Trace from USER_INPUT_SOURCES to EXECUTION_PRIMITIVES
```

---

## IX. QUICK REFERENCE CARD

```
┌─────────────────────────────────────────────────────────────┐
│              MENTAL OS QUICK REFERENCE                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  BEFORE ANYTHING:                                           │
│  □ Code chạy ở đâu?                                         │
│  □ Ai kiểm soát data?                                       │
│  □ Execution boundary ở đâu?                                │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  5-STEP PROCESS:                                            │
│  1. Signal Detection                                        │
│  2. Mechanism Analysis                                      │
│  3. Target Architecture Mapping                             │
│  4. Execution Primitive Check                               │
│  5. Exploit Development (only if steps 1-4 pass)           │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  DENY-FIRST QUESTIONS:                                      │
│  • Input bị sanitize?                                       │
│  • Path có accessible?                                      │
│  • Primitive có tồn tại?                                    │
│  • Barrier có bypass được?                                  │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  RED FLAGS (dừng lại!):                                     │
│  ⚠ Chưa map architecture đã viết payload                   │
│  ⚠ Không giải thích được mechanism                         │
│  ⚠ Chưa thử DENY hypothesis                                │
│  ⚠ Skip bước trong process                                 │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  FORMULA:                                                   │
│  EXPLOIT = Execution Primitive                              │
│          + User-Controlled Data                             │
│          + Reachable Path                                   │
│          - Barriers                                         │
│                                                             │
│  Missing any component = NOT EXPLOITABLE                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## X. CHANGELOG & VERSION

```
Version: 2.0 (Optimized)
Date: 2026-02-04
Changes:
  - Restructured from "thinking → practice → results"
  - Added practical decision trees
  - Added actionable checklists
  - Added real-world examples
  - Added measurement metrics
  - Added quick reference card

Based on: Original Mental Operating System v1.0
```
