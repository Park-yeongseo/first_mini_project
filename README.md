# 일정 관리 마스터 백엔드 API
> FastAPI 기반 AI 연동 일정 관리 백엔드 시스템

## 프로젝트 개요

AI 기반 개인화 일정 관리 서비스의 백엔드 API를 FastAPI로 구현한 프로젝트입니다.
사용자 인증, 루틴 관리, AI 서버 연동을 통한 일정 계획 생성 기능을 제공합니다.

---

## 기술 스택

- **Framework**: FastAPI
- **인증**: JWT (PyJWT)
- **데이터 검증**: Pydantic
- **비밀번호 암호화**: Passlib (bcrypt)
- **HTTP 클라이언트**: httpx (AI 서버 통신)
- **데이터 저장**: In-Memory (리스트/딕셔너리)

---

## API 설계 및 구현

### 인증 시스템
```python
POST /register     # 회원가입
POST /login        # 로그인 (JWT 토큰 발급)
DELETE /logout     # 로그아웃
DELETE /withdraw   # 회원탈퇴
GET /me           # 사용자 정보 조회
POST /me          # 비밀번호 검증
PUT /me           # 사용자 정보 수정
```

### 루틴 관리
```python
POST /routine                    # 루틴 생성 (다중 요일 선택)
GET /routine                     # 사용자 루틴 목록 조회
GET /routine/{week}/{routine_id} # 특정 루틴 상세 조회
PUT /routine/{week}/{routine_id} # 루틴 수정
DELETE /routine/{week}/{routine_id} # 루틴 삭제
```

### AI 일정 플래너
```python
POST /chat        # AI 서버 연동 일정 계획 생성
```

### 계획표 관리
```python
GET /plan         # 계획표 날짜 목록
GET /plan/{date}  # 특정 날짜 계획표 조회
PUT /plan/{date}  # 계획표 수정
DELETE /plan/{date} # 계획표 삭제
GET /api/default-content # 대시보드용 오늘 일정
```

---

## 핵심 구현 사항

### 1. 데이터 모델링 (Pydantic)

**User 모델**
```python
class User(BaseModel):
    login_id: str
    name: str
    password: str
    age: int
    email: str
    user_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: Optional[datetime] = datetime.now()
    routine: RoutineList
    plan: Optional[dict] = {}
```

**Routine 모델**
```python
class Routine(BaseModel):
    routine_id: str = None
    title: str
    routine_time: Optional[time] = None
    time_taken_minutes: Optional[int] = None
    time_zone: Optional[str] = None
```

### 2. 입력 데이터 검증

**사용자 등록 검증**
- 아이디: 5자 이상, 중복 체크
- 이름: 2자 이상, 알파벳만
- 비밀번호: 8자 이상, 특수문자 포함
- 이메일: 정규식 검증

### 3. 보안 구현

**JWT 토큰 시스템**
```python
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now() + (expires_delta or timedelta(hours=1))
    to_encode.update({'exp': expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
```

**비밀번호 암호화**
```python
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)
```

### 4. AI 서버 연동 (핵심 기능)

**OpenAI API 형식으로 요청 처리**
```python
@app.post("/chat", response_model=ChatResponse)
async def request_chat(chat_req: ChatRequest, current_user: User = Depends(get_current_user)):
    # 사용자 컨텍스트 수집 (현재시간, 요일, 루틴, 할 일)
    # OpenAI API 메시지 배열 형식으로 변환
    messages = [
        {"role": "system", "content": system_message},
        {"role": "user", "content": user_message}
    ]
    
    # AI 서버로 비동기 요청
    async with httpx.AsyncClient() as client:
        resp = await client.post(CHAT_SERVER_URL, json=messages, timeout=60.0)
        
    # AI 응답 파싱 및 계획표 저장
    ai_content = response_data["choices"][0]["message"]["content"]
    parsed_plan = json.loads(ai_content)
    
    # 날짜별 계획표 저장
    found_user.plan[today_str] = {
        "plan_table": validated_plan_table,
        "summary": summary,
    }
```

---

## 주요 기술적 도전과 해결

### 1. AI 서버 통신 이슈
**문제**: AI 서버가 예상과 다른 API 형식 요구
```
에러: "Invalid type for 'messages': expected an array of objects"
```

**해결**: OpenAI API 스펙 분석 후 메시지 배열 형식으로 변경
```python
# 변경 전: 객체 형태
payload = {"history": [], "message": "..."}

# 변경 후: 메시지 배열
messages = [
    {"role": "system", "content": "..."},
    {"role": "user", "content": "..."}
]
```

### 2. 시간 데이터 처리
**문제**: timedelta 객체 JSON 직렬화 불가

**해결**: int 타입으로 통일하여 분 단위로 저장
```python
# 변경 전
time_taken_minutes: Optional[timedelta] = None

# 변경 후  
time_taken_minutes: Optional[int] = None
```

---

## 코드 품질 및 구조

### 의존성 주입 활용
```python
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    token = credentials.credentials
    payload = verify_token(token)
    # 사용자 검증 로직
    return user
```

### 예외 처리
```python
# 일관된 HTTP 예외 처리
if not found_user:
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, 
        detail="사용자를 찾을 수 없습니다."
    )
```

### 로깅 및 디버깅
```python
print(f"=== AI 채팅 요청 시작 ===")
print(f"사용자: {current_user.name}")
print(f"AI 서버 응답 상태: {resp.status_code}")
```

---

## 성능 및 확장성 고려사항

### 비동기 처리
- AI 서버 통신을 async/await로 처리
- httpx.AsyncClient 사용으로 비블로킹 HTTP 요청

### 에러 핸들링
- 타임아웃, 연결 실패, HTTP 오류별 구분 처리
- 사용자 친화적 오류 메시지 제공

### CORS 설정
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

---

## 데이터베이스 설계 (In-Memory)

```python
# 사용자 정보 저장
users = []  # [{user_id: User 객체}]

# 대화 기록 저장 (AI 맥락 유지)
conversation_history = {}  # {user_id: [messages]}

# 탈퇴 사용자 보관
removed_users = []
```

---

## 테스트 및 검증

### API 엔드포인트 테스트
- 각 CRUD 기능별 정상/오류 케이스 검증
- JWT 인증 토큰 생성/검증 테스트
- AI 서버 연동 통신 테스트

### 데이터 검증
- Pydantic 모델을 통한 입력값 자동 검증
- 커스텀 validator로 비즈니스 로직 검증

---

## 향후 개선 방향

### 단기 개선
- SQLite 데이터베이스 연동 (파일 기반 영구 저장)
- 환경변수를 통한 설정 관리 (.env 파일)

### 장기 발전
- PostgreSQL 연동으로 확장
- 파일 업로드 기능 추가

---

## 결론

이 프로젝트를 통해 다음을 구현했습니다:

**기술적 성취**
- FastAPI 기반 RESTful API 설계
- JWT 인증 시스템 구현
- 외부 AI 서버와의 안정적 연동
- Pydantic을 활용한 데이터 검증

**문제 해결 역량**
- API 스펙 불일치 문제 분석 및 해결
- 비동기 처리를 통한 성능 최적화
- 체계적인 오류 처리 및 로깅

실제 프로덕션 환경에서 사용 가능한 수준의 백엔드 API를 구현했으며, AI 서비스와의 연동을 통해 현대적인 백엔드 개발 역량을 입증했습니다.