# MENTAL OPERATING SYSTEM - PHIÊN BẢN THỰC HÀNH

## Triết lý: Không lý thuyết, chỉ có HÀNH ĐỘNG và KẾT QUẢ

---

## PHẦN 0: AI LÀM GÌ? HUMAN LÀM GÌ?

### Phân Chia Vai Trò Rõ Ràng

```
┌─────────────────────────────────────────────────────────────────────┐
│                        HUMAN (Bạn)                                  │
├─────────────────────────────────────────────────────────────────────┤
│  • Đưa ra TARGET (CVE, URL, source code)                           │
│  • Đặt câu hỏi đúng                                                 │
│  • Ra quyết định cuối cùng (exploit hay không)                     │
│  • Chịu trách nhiệm về ethics và legality                          │
│  • Verify kết quả bằng tay khi cần                                 │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                          AI (Tôi)                                   │
├─────────────────────────────────────────────────────────────────────┤
│  • Thu thập thông tin (CVE details, code analysis)                 │
│  • Phân tích mechanism                                              │
│  • Map architecture                                                 │
│  • Tìm execution primitives                                         │
│  • Generate DENY reasons (tại sao KHÔNG exploit được)              │
│  • Đề xuất PoC nếu exploitable                                     │
│  • Loop lại nếu sai                                                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## PHẦN 1: QUY TRÌNH THỰC TẾ - TỪNG BƯỚC CỤ THỂ

### BƯỚC 1: HUMAN ĐƯA INPUT

**Human làm:**
```
Cung cấp MỘT trong các input sau:
  A) CVE ID: "CVE-2025-29927"
  B) Target URL: "https://example.com"
  C) Source code path: "/path/to/code"
  D) Bug description: "Tìm thấy eval() với user input"
```

**AI nhận và xác nhận:**
```
"Tôi nhận được: [INPUT]
Bắt đầu quy trình phân tích.
Bước tiếp theo: Thu thập thông tin cơ bản."
```

---

### BƯỚC 2: AI THU THẬP THÔNG TIN

**AI làm cụ thể:**

```
IF input = CVE:
    1. Fetch CVE details từ NVD/CVE database
    2. Tìm affected versions
    3. Đọc advisory/patch
    4. Xác định vulnerability type

IF input = Source code:
    1. Identify framework/language
    2. Find entry points (routes, handlers)
    3. Locate sensitive functions
    4. Map data flow

IF input = URL:
    1. Fingerprint technology stack
    2. Identify framework version
    3. Map visible endpoints
    4. Check for known CVEs
```

**Output bắt buộc của bước này:**

```markdown
## Thông Tin Thu Thập

**Target:** [tên/URL]
**Stack:** [framework] [version]
**Vulnerability Type:** [RCE/SQLi/XSS/Auth Bypass/...]
**Affected Component:** [file/function/route]

**Câu hỏi cần trả lời ở bước tiếp:**
1. Mechanism hoạt động như thế nào?
2. User input có đến được component này không?
```

---

### BƯỚC 3: AI PHÂN TÍCH MECHANISM

**Câu hỏi AI phải tự trả lời:**

```
1. Bug xảy ra ở LAYER nào?
   □ Routing (URL handling, redirects)
   □ Middleware (pre-processing, auth checks)
   □ Application Logic (business code)
   □ Runtime (code execution, eval)

2. Điều kiện TRIGGER là gì?
   → Cần header gì?
   → Cần parameter gì?
   → Cần request method gì?
   → Cần authentication không?

3. Impact LÝ THUYẾT là gì?
   → Nếu trigger được, chuyện gì xảy ra?
```

**AI phải output:**

```markdown
## Mechanism Analysis

**Layer:** [Routing/Middleware/Logic/Runtime]

**Trigger Conditions:**
- Method: [GET/POST/...]
- Path: [/path/to/vulnerable]
- Headers: [required headers]
- Body: [required params]
- Auth: [required/not required]

**Theoretical Impact:**
- Nếu trigger: [mô tả impact]
- Severity: [Critical/High/Medium/Low]

**Câu hỏi quan trọng:**
- Layer này có EXECUTION PRIMITIVE không?
  → Routing: KHÔNG có (chỉ redirect/rewrite)
  → Middleware: KHÔNG có (chỉ check/block)
  → Logic: CÓ THỂ có (nếu có eval, exec, template)
  → Runtime: CÓ (direct code execution)
```

---

### BƯỚC 4: AI KIỂM TRA EXECUTION PRIMITIVE

**Đây là bước QUAN TRỌNG NHẤT**

**AI phải làm:**

```
1. TÌM execution primitives trong code:

   DANGEROUS (có thể RCE):
   ├── eval()
   ├── Function()
   ├── new Function()
   ├── setTimeout/setInterval với string
   ├── vm.runInContext()
   ├── child_process.exec/spawn
   ├── require() với dynamic path
   ├── import() với dynamic path
   └── Template engines (EJS, Pug, Handlebars)

   DANGEROUS (có thể data leak):
   ├── SQL queries với string concat
   ├── fs.readFile với user path
   ├── fetch/axios với user URL
   └── Deserialization functions

2. TRACE data flow:
   User Input → ... → Execution Primitive?

   Nếu KHÔNG có path: KHÔNG EXPLOITABLE
   Nếu CÓ path: Kiểm tra barriers
```

**AI output:**

```markdown
## Execution Primitive Check

**Primitives Found:**
- [x] eval() tại line 123 của file.js
- [ ] Function() - không tìm thấy
- [x] child_process.exec tại line 456

**Data Flow Analysis:**
```
User Input: req.query.cmd
    ↓
Validation: sanitize() ← BARRIER?
    ↓
Processing: processCommand()
    ↓
Execution: exec(cmd) ← PRIMITIVE
```

**Barriers Detected:**
- [ ] Input validation/sanitization
- [ ] Allowlist check
- [ ] Type checking
- [ ] Sandbox/jail

**Verdict:** [CÓ/KHÔNG CÓ] execution path
```

---

### BƯỚC 5: AI THỬ DENY (BÁC BỎ)

**AI BẮT BUỘC phải làm bước này TRƯỚC khi kết luận exploitable**

**AI tự hỏi và trả lời:**

```markdown
## DENY Analysis - Tại sao KHÔNG exploit được?

### Lý do 1: Input không reach được primitive
- User input bắt đầu từ: [đâu]
- Primitive nằm ở: [đâu]
- Path có thông không: [CÓ/KHÔNG]
- Nếu KHÔNG: → DENY THÀNH CÔNG → NOT EXPLOITABLE

### Lý do 2: Có barrier chặn
- Validation: [có/không] [bypass được không]
- Sanitization: [có/không] [bypass được không]
- Type check: [có/không] [bypass được không]
- Allowlist: [có/không] [bypass được không]
- Nếu có barrier KHÔNG bypass được: → DENY THÀNH CÔNG

### Lý do 3: Primitive không dangerous
- Primitive type: [gì]
- Có thể execute arbitrary code không: [CÓ/KHÔNG]
- Nếu KHÔNG: → DENY THÀNH CÔNG

### Lý do 4: Cần điều kiện không thể đạt
- Cần auth: [loại gì] [có thể bypass không]
- Cần internal access: [có/không]
- Cần specific config: [có/không]
- Nếu điều kiện KHÔNG thể đạt: → DENY THÀNH CÔNG

### Lý do 5: Version/Config
- Version đã patch: [có/không]
- Feature disabled: [có/không]
- Nếu CÓ: → DENY THÀNH CÔNG

---

**DENY RESULT:**
□ Tìm được lý do deny → NOT EXPLOITABLE
□ Không tìm được lý do deny → PROCEED TO EXPLOIT
```

---

### BƯỚC 6: KẾT LUẬN VÀ HÀNH ĐỘNG

**Nếu DENY thành công:**

```markdown
## Kết Luận: NOT EXPLOITABLE

**Lý do chính:** [lý do deny mạnh nhất]

**Evidence:**
- [code snippet chứng minh]
- [config chứng minh]

**Confidence:** [High/Medium/Low]

**Recommendation:**
- Không cần action
- Hoặc: Monitor nếu conditions thay đổi
```

**Nếu DENY thất bại (không tìm được lý do):**

```markdown
## Kết Luận: POTENTIALLY EXPLOITABLE

**Execution Path:**
User Input → [path] → Primitive

**Minimal PoC:**
```bash
curl -X POST https://target.com/vuln \
  -H "Content-Type: application/json" \
  -d '{"cmd": "id"}'
```

**Expected Result:**
- Nếu vulnerable: [expected output]
- Nếu patched: [expected output]

**Next Step:** Human verify PoC
```

---

## PHẦN 2: LOOP TỰ ĐỘNG - KHI KẾT QUẢ SAI

### Khi PoC Fail

```
┌─────────────────────────────────────────────────────────────────┐
│  PoC FAIL                                                       │
│      │                                                          │
│      ▼                                                          │
│  AI tự hỏi: Tại sao fail?                                      │
│      │                                                          │
│      ├─► Hypothesis 1: Có barrier chưa detect                  │
│      │       → Quay lại BƯỚC 4, tìm barriers                   │
│      │                                                          │
│      ├─► Hypothesis 2: Mechanism analysis sai                  │
│      │       → Quay lại BƯỚC 3, re-analyze                     │
│      │                                                          │
│      ├─► Hypothesis 3: Data flow analysis sai                  │
│      │       → Quay lại BƯỚC 4, re-trace                       │
│      │                                                          │
│      └─► Hypothesis 4: Target đã patch                         │
│              → Update DENY, kết luận NOT EXPLOITABLE           │
│                                                                 │
│  KHÔNG BAO GIỜ: Viết payload mới mà không hiểu tại sao fail   │
└─────────────────────────────────────────────────────────────────┘
```

### AI Self-Correction Protocol

```markdown
## Khi Cần Loop Lại

**Trigger:** PoC fail hoặc kết quả không như expected

**AI làm:**

1. Log failure reason:
   "PoC fail vì: [lý do observed]"

2. Identify gap:
   "Điều tôi chưa biết: [gap]"

3. Plan correction:
   "Cần làm lại: [bước nào]"

4. Execute correction:
   [Thực hiện lại bước đó]

5. Re-verify:
   "Kết quả mới: [result]"

**KHÔNG BAO GIỜ:**
- Guess payload mới
- Try random variations
- Brute force
```

---

## PHẦN 3: VÍ DỤ THỰC TẾ - FULL WALKTHROUGH

### Ví dụ: CVE-2025-29927 (Next.js Middleware Bypass)

**BƯỚC 1: Human Input**
```
Human: "Analyze CVE-2025-29927 for target https://shop.example.com"
```

**BƯỚC 2: AI Thu Thập**
```markdown
## Thông Tin Thu Thập

**Target:** shop.example.com
**Stack:** Next.js 14.2.20
**Vulnerability Type:** Authorization Bypass
**Affected Component:** Middleware layer

**CVE Details:**
- Affected: Next.js < 15.2.3, < 14.2.25
- Trigger: x-middleware-subrequest header
- Impact: Bypass middleware checks
```

**BƯỚC 3: AI Phân Tích Mechanism**
```markdown
## Mechanism Analysis

**Layer:** ROUTING (không phải Runtime!)

**Trigger Conditions:**
- Method: Any
- Path: Any path có middleware
- Headers: x-middleware-subrequest: 1
- Auth: Not required

**Theoretical Impact:**
- Bypass middleware logic
- Access routes protected by middleware

**CRITICAL INSIGHT:**
- Routing layer KHÔNG có execution primitive
- Bypass middleware ≠ RCE
- Chỉ bypass được những gì middleware làm
```

**BƯỚC 4: AI Check Primitive**
```markdown
## Execution Primitive Check

**Middleware source (target):**
```javascript
// middleware.ts
export function middleware(request) {
  const token = request.cookies.get('auth');
  if (!token) {
    return NextResponse.redirect('/login');
  }
  // Allow request to continue
}
```

**Primitive Analysis:**
- Middleware chỉ có: redirect, rewrite, set headers
- KHÔNG có: eval, exec, database query, file access

**Data Flow:**
- User request → Middleware check → Route handler
- Bypass middleware = Skip check
- Route handler vẫn cần xử lý business logic

**Verdict:** KHÔNG CÓ execution primitive ở middleware layer
```

**BƯỚC 5: AI DENY**
```markdown
## DENY Analysis

### Lý do 1: Layer không có primitive ✓
- Middleware chỉ làm: auth check, redirect
- Không có code execution capability
- **DENY PARTIALLY SUCCESSFUL**

### Lý do 2: Defense in depth?
- API routes có auth check riêng không?
- Checking...

```javascript
// pages/api/admin/users.ts
export default async function handler(req, res) {
  const session = await getSession(req);  // ← Auth check tại API!
  if (!session?.isAdmin) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  // ... business logic
}
```

- **API routes có independent auth check**
- **DENY SUCCESSFUL cho API routes**

### Lý do 3: UI routes?
- UI routes có sensitive data không?
- Checking pages...
- /admin/dashboard → Shows admin UI nhưng data từ API
- API protected → Data protected
- **DENY SUCCESSFUL**

---

**DENY RESULT:** ✓ Tìm được lý do deny
```

**BƯỚC 6: Kết Luận**
```markdown
## Kết Luận: LIMITED EXPLOITABILITY

**Có thể exploit:**
- Access admin UI routes (visual only)
- Bypass middleware-only checks

**KHÔNG thể exploit:**
- API endpoints (có independent auth)
- Sensitive data (fetched via API)
- Admin actions (require API auth)

**Real Impact:** LOW
- Attacker thấy admin UI layout
- Attacker KHÔNG thể perform admin actions
- Attacker KHÔNG thể access sensitive data

**Recommendation:**
- Patch Next.js (vẫn nên làm)
- Nhưng không phải critical emergency
```

---

## PHẦN 4: CHECKLIST THỰC HÀNH CHO HUMAN

### Trước Khi Bắt Đầu

```
□ Có authorization để test target này không?
□ Có đủ thông tin (CVE/URL/code) chưa?
□ Mục tiêu là gì? (Verify exploitability / Find vulns / Learn)
```

### Trong Quá Trình

```
□ AI có đủ 6 bước không?
□ AI có làm DENY analysis không?
□ AI có evidence cho mỗi claim không?
□ Kết luận có logical không?
```

### Sau Khi Xong

```
□ Kết quả có verify được không?
□ Nếu PoC, đã test chưa?
□ Nếu NOT EXPLOITABLE, lý do có convincing không?
□ Cần report/document gì không?
```

---

## PHẦN 5: COMMON MISTAKES VÀ CÁCH TRÁNH

### Mistake 1: Nhảy thẳng vào payload

```
❌ SAI:
Human: "CVE-2025-29927"
AI: "Đây là payload: curl -H 'x-middleware-subrequest: 1' ..."

✅ ĐÚNG:
AI: "Để tôi phân tích mechanism trước..."
[6 bước đầy đủ]
AI: "Kết luận: Limited impact vì..."
```

### Mistake 2: Không làm DENY

```
❌ SAI:
AI: "Có CVE → có exploit"

✅ ĐÚNG:
AI: "Có CVE → cần verify với target cụ thể"
AI: "Lý do có thể KHÔNG exploit: [danh sách]"
AI: "Sau khi check: [kết luận]"
```

### Mistake 3: Confuse layers

```
❌ SAI:
"Middleware bypass = có thể RCE"

✅ ĐÚNG:
"Middleware bypass = bypass middleware logic only"
"RCE cần execution primitive ở runtime layer"
```

### Mistake 4: Loop sai cách

```
❌ SAI:
PoC fail → Thử payload khác → Fail → Thử payload khác...

✅ ĐÚNG:
PoC fail → Tại sao fail? → Re-analyze → Hiểu rồi mới thử lại
```

---

## PHẦN 6: METRICS - BIẾT KHI NÀO MÌNH ĐÚNG

### Signals của phân tích TỐT

```
✓ Có thể giải thích mechanism bằng lời đơn giản
✓ Có evidence (code, config, output) cho mỗi claim
✓ DENY analysis có ít nhất 3 lý do được check
✓ Kết luận có confidence level
✓ Nếu có PoC, PoC có expected output rõ ràng
```

### Signals của phân tích TỒI

```
✗ Không giải thích được tại sao
✗ Chỉ có claims, không có evidence
✗ Không có DENY analysis
✗ Kết luận mơ hồ ("có thể", "maybe")
✗ PoC không có expected output
```

---

## PHẦN 7: TEMPLATES SỬ DỤNG NGAY

### Template 1: Request AI Analyze

```
Analyze [CVE-XXXX / target URL / code path] theo quy trình:
1. Thu thập thông tin
2. Phân tích mechanism
3. Check execution primitive
4. DENY analysis (tại sao KHÔNG exploit được)
5. Kết luận với evidence
```

### Template 2: AI Response Format

```markdown
## Analysis: [Target/CVE]

### 1. Information Gathered
- Stack:
- Version:
- Component:

### 2. Mechanism
- Layer:
- Trigger:
- Theoretical impact:

### 3. Execution Primitive Check
- Primitives found:
- Data flow:
- Barriers:

### 4. DENY Analysis
- Reason 1: [check/not check]
- Reason 2: [check/not check]
- Reason 3: [check/not check]

### 5. Conclusion
- Verdict: [EXPLOITABLE/NOT EXPLOITABLE/LIMITED]
- Evidence: [code/config/output]
- Confidence: [High/Medium/Low]
- Next step: [action]
```

### Template 3: PoC Format (nếu exploitable)

```markdown
## PoC: [Target/CVE]

### Prerequisites
- Version: must be [version]
- Config: must have [config]
- Access: need [access level]

### Steps
1. [step 1]
2. [step 2]
3. [step 3]

### Command
```bash
[actual command]
```

### Expected Output
- If vulnerable: [output]
- If patched: [output]

### Verification
[How to verify success]
```

---

## TÓM TẮT: FLOW HOÀN CHỈNH

```
┌─────────────────────────────────────────────────────────────────┐
│  HUMAN: Đưa target (CVE/URL/Code)                              │
│      │                                                          │
│      ▼                                                          │
│  AI: Thu thập thông tin                                        │
│      │                                                          │
│      ▼                                                          │
│  AI: Phân tích mechanism (layer, trigger, impact)              │
│      │                                                          │
│      ▼                                                          │
│  AI: Check execution primitive (có/không, path, barriers)      │
│      │                                                          │
│      ▼                                                          │
│  AI: DENY analysis (tìm lý do KHÔNG exploit được)              │
│      │                                                          │
│      ├──► DENY thành công → NOT EXPLOITABLE                    │
│      │                                                          │
│      └──► DENY thất bại → POTENTIALLY EXPLOITABLE              │
│               │                                                 │
│               ▼                                                 │
│           AI: Generate PoC                                      │
│               │                                                 │
│               ▼                                                 │
│           HUMAN: Verify PoC                                     │
│               │                                                 │
│               ├──► Success → CONFIRMED EXPLOITABLE             │
│               │                                                 │
│               └──► Fail → AI loop lại (tìm hiểu tại sao)       │
│                       │                                         │
│                       ▼                                         │
│                   [Quay lại bước phù hợp]                      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

**Version:** 3.0 (Practical)
**Focus:** Hành động cụ thể, không lý thuyết
**Motto:** "Hiểu trước, làm sau. Deny trước, exploit sau."
