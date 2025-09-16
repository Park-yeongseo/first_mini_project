# main.py

from datetime import datetime
from typing import List, Optional
import uuid
from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import httpx
from app.models import (
    ChatRequest,
    ChatResponse,
    CreateRoutine,
    DecisionUpdate,
    GetPlan,
    GetPlanDate,
    Routine,
    RoutineList,
    RoutineTitleList,
    Token,
    UpdateRoutine,
    User,
    UserLogin,
    UserResponse,
    UserUpdate,
)
from app.utils import create_access_token, verify_token
from datas.users import hash_password, users, removed_users, conversation_history, verify_password


# FastAPI 애플리케이션 생성
app = FastAPI()

# CORS(Cross-Origin Resource Sharing) 미들웨어 추가
# 모든 출처, 자격 증명, 메서드, 헤더를 허용하도록 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# HTTP Bearer Token을 사용하는 보안 객체 생성
security = HTTPBearer()

# 챗봇 서버 URL
CHAT_SERVER_URL = "https://dev.wenivops.co.kr/services/openai-api"


# 현재 로그인된 사용자를 가져오는 의존성 함수
# Authorization 헤더의 토큰을 검증하여 사용자 정보를 반환
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> User:
    token = credentials.credentials
    # 토큰 검증
    payload = verify_token(token)
    user_id = payload["sub"]

    # 사용자 목록에서 사용자 ID로 사용자 정보 검색
    for user_info_dict in users:
        if user_id in user_info_dict:
            return user_info_dict[user_id]
            
    # 사용자를 찾지 못한 경우 404 에러 발생
    raise HTTPException(status.HTTP_404_NOT_FOUND, detail="사용자를 찾을 수 없습니다.")


# --- 회원 관리 및 인증 엔드포인트 ---

@app.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(user: User):
    """
    새로운 사용자를 등록합니다.
    - 비밀번호를 해시하여 저장합니다.
    - 사용자 ID를 키로 하여 conversation_history에 시스템 메시지를 추가합니다.
    """
    user.password = hash_password(user.password)
    users.append({user.user_id: user})
    conversation_history.update(
        {
            user.user_id: [
                {
                    "role": "system",
                    "message": "너는 일정 관리 마스터야. 사용자의 요청 정보와  사용자의 루틴을 고려해서 약간 여유롭게 보수적으로 계획표 형태로 정리해줘.",
                }
            ]
        }
    )
    return user


@app.post("/login", response_model=Token)
def user_login(user: UserLogin):
    """
    사용자 로그인 및 JWT 토큰을 발급합니다.
    - 입력된 아이디와 비밀번호를 검증합니다.
    - 검증 성공 시, access_token을 생성하여 반환합니다.
    """
    found_user = None
    for user_info_dict in users:
        for user_id, user_info in user_info_dict.items():
            if user_info.login_id == user.login_id:
                found_user = user_info
                break
        if found_user:
            break

    # 사용자를 찾지 못한 경우
    if not found_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="회원이 아닙니다."
        )

    # 비밀번호가 일치하지 않는 경우
    if not verify_password(user.password, found_user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="비밀번호가 틀렸습니다."
        )

    # 토큰에 포함될 데이터
    data = {"sub": found_user.user_id}
    access_token = create_access_token(data)
    return {"access_token": access_token, "token_type": "Bearer"}


@app.delete("/logout")
def user_logout(user: User = Depends(get_current_user)):
    """
    사용자 로그아웃 (실제로는 서버 측에서 할 일이 없음. 토큰 만료를 기다림)
    """
    return {"message": "로그아웃 되었습니다."}


@app.delete("/withdraw", response_model=Optional[UserResponse])
def user_withdraw(user: User = Depends(get_current_user)):
    """
    회원 탈퇴를 처리합니다.
    - users 목록에서 해당 사용자를 삭제하고 removed_users 목록에 추가합니다.
    """
    for i, user_dict in enumerate(users):
        if user.user_id in user_dict:
            removed_data = users.pop(i)
            removed_users.append(removed_data)
            return removed_data
    return None


@app.get("/me", response_model=UserResponse)
def get_me(user: User = Depends(get_current_user)):
    """
    현재 로그인된 사용자의 정보를 반환합니다.
    """
    return user


@app.post("/me", response_model=UserResponse)
def decision_delete(password: DecisionUpdate, user: User = Depends(get_current_user)):
    """
    회원 탈퇴 전 비밀번호를 확인합니다.
    """
    if verify_password(password.password, user.password):
        return user
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST, detail="비밀번호가 일치하지 않습니다."
    )


@app.put("/me", response_model=UserResponse)
def update_me(updated_user: UserUpdate, current_user: User = Depends(get_current_user)):
    """
    현재 로그인된 사용자의 정보를 수정합니다.
    - 이름, 비밀번호, 나이, 이메일을 업데이트합니다.
    """
    found_user = None
    for user_info_dict in users:
        if current_user.user_id in user_info_dict:
            found_user = user_info_dict[current_user.user_id]
            break

    if updated_user.name is not None:
        found_user.name = updated_user.name
    if updated_user.password is not None:
        found_user.password = hash_password(updated_user.password)
    if updated_user.age is not None:
        found_user.age = updated_user.age
    if updated_user.email is not None:
        found_user.email = updated_user.email

    return found_user


# --- 루틴 관리 엔드포인트 ---

@app.post("/routine", response_model=Routine)
def create_routine(
    created_routine: CreateRoutine, current_user: User = Depends(get_current_user)
):
    """새로운 루틴을 생성하여 사용자 루틴 목록에 추가합니다."""
    print(f"=== 루틴 생성 요청 ===")
    print(f"사용자: {current_user.name}")
    print(f"루틴 데이터: {created_routine}")
    
    found_user = None
    for i in users:
        if current_user.user_id in i:
            found_user = i[current_user.user_id]
            break

    if not found_user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="사용자를 찾을 수 없습니다.")

    # 루틴이 추가되었는지 확인하는 플래그
    added = False
    new_routine = None
    
    # 각 요일별로 루틴 추가
    days_to_add = []
    if created_routine.monday: days_to_add.append('monday')
    if created_routine.tuesday: days_to_add.append('tuesday')
    if created_routine.wednesday: days_to_add.append('wednesday')
    if created_routine.thursday: days_to_add.append('thursday')
    if created_routine.friday: days_to_add.append('friday')
    if created_routine.saturday: days_to_add.append('saturday')
    if created_routine.sunday: days_to_add.append('sunday')
    
    if not days_to_add:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="최소 하나의 요일을 선택해야 합니다."
        )
    
    for day in days_to_add:
        new_routine = Routine(
            routine_id=str(uuid.uuid4()),
            title=created_routine.title,
            routine_time=created_routine.routine_time,
            time_taken_minutes=created_routine.time_taken_minutes,
            time_zone=created_routine.time_zone
        )
        getattr(found_user.routine, day).append(new_routine)
        added = True
        print(f"루틴 추가: {day} - {new_routine.title}")
        
    return new_routine


@app.get("/routine", response_model=RoutineList)  # RoutineTitleList 대신 RoutineList
def get_my_routinelist(current_user: User = Depends(get_current_user)):
    """
    로그인된 사용자의 전체 루틴 목록을 반환합니다.
    """
    print(f"=== 루틴 목록 조회 ===")
    print(f"사용자: {current_user.name}")
    
    # 루틴 데이터 확인
    for day in ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']:
        routines = getattr(current_user.routine, day, [])
        print(f"{day}: {len(routines)}개 루틴")
        for i, routine in enumerate(routines):
            print(f"  - {i}: ID={routine.routine_id}, 제목={routine.title}")
    
    return current_user.routine


week_list = [
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
]


@app.get("/routine/{week}/{routine_id}", response_model=Routine)
def get_routine_detail(
    week: str, routine_id: str, current_user: User = Depends(get_current_user)
):
    """
    특정 요일의 특정 루틴 상세 정보를 반환합니다.
    """
    if week not in week_list:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="잘못된 주소입니다.")
    
    week_routine = getattr(current_user.routine, week)
    for i in week_routine:
        if i.routine_id == routine_id:
            return i
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail="루틴을 찾을 수 없습니다."
    )


@app.put("/routine/{week}/{routine_id}", response_model=Routine)
def update_routine(
    updated_routine: UpdateRoutine,
    week: str,
    routine_id: str,
    current_user: User = Depends(get_current_user),
):
    """특정 루틴의 정보를 수정합니다."""
    print(f"=== 루틴 수정 요청 ===")
    print(f"사용자: {current_user.name}")
    print(f"요일: {week}, 루틴 ID: {routine_id}")
    print(f"수정 데이터: {updated_routine}")
    
    if week not in week_list:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="잘못된 주소입니다.")

    found_user = None
    for user_info_dict in users:
        if current_user.user_id in user_info_dict:
            found_user = user_info_dict[current_user.user_id]
            break
    
    if not found_user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="사용자를 찾을 수 없습니다.")
            
    found_user_routine = getattr(found_user.routine, week)
    
    for i, r in enumerate(found_user_routine):
        if r.routine_id == routine_id:
            # 기존 routine_id를 유지하면서 새 데이터로 업데이트
            new_routine = Routine(
                routine_id=routine_id,
                title=updated_routine.title,
                routine_time=updated_routine.routine_time,
                time_taken_minutes=updated_routine.time_taken_minutes,
                time_zone=updated_routine.time_zone
            )
            found_user_routine[i] = new_routine
            print(f"✅ 루틴 수정 완료: {new_routine}")
            return new_routine
            
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail="루틴을 찾을 수 없습니다."
    )


@app.delete("/routine/{week}/{routine_id}", response_model=Routine)
def remove_routine(
    week: str, routine_id: str, current_user: User = Depends(get_current_user)
):
    """특정 루틴을 삭제합니다."""
    print(f"=== 루틴 삭제 요청 ===")
    print(f"사용자: {current_user.name}")
    print(f"요일: {week}, 삭제할 루틴 ID: {routine_id}")
    
    if week not in week_list:
        print(f"❌ 잘못된 요일: {week}")
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="잘못된 주소입니다.")

    found_user = None
    for user_info_dict in users:
        if current_user.user_id in user_info_dict:
            found_user = user_info_dict[current_user.user_id]
            break

    if not found_user:
        print("❌ 사용자를 찾을 수 없음")
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="사용자를 찾을 수 없습니다.")

    found_user_routine = getattr(found_user.routine, week)
    print(f"해당 요일의 루틴 개수: {len(found_user_routine)}")
    
    # 모든 루틴의 ID 출력
    for i, routine in enumerate(found_user_routine):
        print(f"루틴 {i}: ID={routine.routine_id}, 제목={routine.title}")
    
    for i, r in enumerate(found_user_routine):
        if r.routine_id == routine_id:
            deleted_routine = found_user_routine.pop(i)
            print(f"✅ 루틴 삭제 완료: {deleted_routine.title}")
            return deleted_routine
    
    print(f"❌ 루틴 ID를 찾을 수 없음: {routine_id}")
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail="루틴을 찾을 수 없습니다."
    )


# --- 챗봇 및 계획표 관리 엔드포인트 ---

@app.post("/chat", response_model=ChatResponse)
async def request_chat(
    chat_req: ChatRequest, current_user: User = Depends(get_current_user)
):
    """
    AI 서버에 대화 기록과 함께 일정 계획 요청을 보냅니다.
    """
    print(f"=== AI 채팅 요청 시작 ===")
    print(f"사용자: {current_user.name} (ID: {current_user.user_id})")
    print(f"메시지: {chat_req.message}")
    print(f"할 일 개수: {len(chat_req.tasks)}")
    
    # 현재 시간, 요일 정보
    current_time = datetime.now().strftime("%H:%M")
    current_weekday = datetime.now().strftime("%A").lower()
    today_str = datetime.now().strftime("%Y-%m-%d")
    
    print(f"현재 시간: {current_time}, 요일: {current_weekday}, 날짜: {today_str}")

    # 사용자 루틴 정보 수집
    user_routine_text = ""
    try:
        weekly_routines = getattr(current_user.routine, current_weekday, [])
        if weekly_routines:
            routine_items = []
            for routine in weekly_routines:
                routine_info = f"- {routine.title}"
                if routine.routine_time:
                    try:
                        routine_info += f" ({routine.routine_time.strftime('%H:%M')})"
                    except:
                        pass
                if routine.time_taken_minutes:
                    try:
                        if hasattr(routine.time_taken_minutes, 'total_seconds'):
                            minutes = int(routine.time_taken_minutes.total_seconds() / 60)
                        else:
                            minutes = int(routine.time_taken_minutes)
                        routine_info += f" - {minutes}분 소요"
                    except:
                        pass
                if routine.time_zone:
                    routine_info += f" - {routine.time_zone}"
                routine_items.append(routine_info)
            user_routine_text = "\n".join(routine_items)
        else:
            user_routine_text = "설정된 루틴이 없습니다."
    except Exception as e:
        print(f"루틴 처리 오류: {e}")
        user_routine_text = "루틴 정보를 불러올 수 없습니다."

    # 할 일 정보 수집
    tasks_text = ""
    if chat_req.tasks:
        task_items = []
        for i, task in enumerate(chat_req.tasks):
            task_info = f"- {task.title}"
            if task.expected_duration:
                task_info += f" (예상 소요: {task.expected_duration}분)"
            if task.target_start_time:
                try:
                    task_info += f" (목표 시작: {task.target_start_time.strftime('%H:%M')})"
                except:
                    pass
            if task.additional_info:
                task_info += f" - {task.additional_info}"
            task_items.append(task_info)
        tasks_text = "\n".join(task_items)
    else:
        tasks_text = "등록된 할 일이 없습니다."

    print(f"루틴 정보: {user_routine_text}")
    print(f"할 일 정보: {tasks_text}")

    # 기존 대화 기록 가져오기
    history = conversation_history.get(current_user.user_id, [])
    
    # 대화 기록을 AI 서버 형식으로 변환
    messages = []
    
    # 시스템 메시지 (AI 역할 정의)
    system_content = f"""당신은 전문적인 일정 관리 AI 어시스턴트입니다.

현재 상황:
- 현재 시간: {current_time}
- 현재 요일: {current_weekday} 
- 날짜: {today_str}

사용자의 오늘 루틴:
{user_routine_text}

사용자의 할 일:
{tasks_text}

역할: 사용자의 루틴과 할 일을 고려하여 현실적이고 효율적인 하루 일정을 계획해주세요.

응답 형식: 반드시 다음 JSON 형식으로만 응답하세요:
{{"response": "사용자에게 보여줄 친근한 메시지", "plan_table": [{{"time": "09:00", "title": "일정 제목", "description": "상세 설명"}}], "summary": "오늘 일정 요약"}}

주의사항:
- plan_table은 시간 순으로 정렬
- 각 일정 간 이동시간과 휴식시간 고려
- JSON 형식을 정확히 준수"""

    messages.append({"role": "system", "content": system_content})
    
    # 기존 대화 기록 추가
    for msg in history:
        if msg["role"] == "user":
            messages.append({"role": "user", "content": msg["message"]})
        elif msg["role"] == "assistant":
            # assistant 메시지 처리
            if isinstance(msg["message"], dict):
                assistant_content = msg["message"].get("response", "")
            else:
                assistant_content = str(msg["message"])
            if assistant_content:
                messages.append({"role": "assistant", "content": assistant_content})
    
    # 현재 사용자 메시지 추가
    current_message = chat_req.message or "오늘 하루 일정을 계획해주세요."
    messages.append({"role": "user", "content": current_message})
    
    print(f"전송할 메시지 수: {len(messages)}")
    print(f"마지막 사용자 메시지: {current_message}")

    try:
        # AI 서버로 요청 전송 (배열 형식)
        async with httpx.AsyncClient() as client:
            print("AI 서버로 대화 기록과 함께 요청 전송 중...")
            
            # 요청 본문은 메시지 배열만
            resp = await client.post(
                CHAT_SERVER_URL, 
                json=messages,  # 배열을 직접 전송
                timeout=60.0,
                headers={"Content-Type": "application/json"}
            )
            
            print(f"AI 서버 응답 상태: {resp.status_code}")
            
            if resp.status_code != 200:
                print(f"AI 서버 오류 응답: {resp.text}")
                resp.raise_for_status()
            
            # 응답 파싱
            response_data = resp.json()
            print(f"AI 서버 원본 응답 구조: {list(response_data.keys())}")
            
            # AI 응답에서 content 추출
            if "choices" in response_data and len(response_data["choices"]) > 0:
                ai_content = response_data["choices"][0]["message"]["content"]
                print(f"AI 생성 내용: {ai_content[:200]}...")
            else:
                raise ValueError("AI 응답에서 choices를 찾을 수 없습니다")
            
            # AI가 생성한 JSON 파싱
            try:
                import re
                import json
                
                # JSON 부분만 추출
                json_match = re.search(r'\{.*\}', ai_content, re.DOTALL)
                if json_match:
                    json_str = json_match.group(0)
                    parsed_data = json.loads(json_str)
                    print(f"파싱 성공: response={len(parsed_data.get('response', ''))}, plan_table={len(parsed_data.get('plan_table', []))}")
                else:
                    # JSON이 없으면 기본 응답 생성
                    parsed_data = {
                        "response": ai_content,
                        "plan_table": [],
                        "summary": "AI가 계획표 형식으로 응답하지 않았습니다."
                    }
                    print("JSON 형식을 찾을 수 없어 기본 응답 사용")
                
            except json.JSONDecodeError as e:
                print(f"JSON 파싱 오류: {e}")
                parsed_data = {
                    "response": ai_content,
                    "plan_table": [],
                    "summary": "응답을 파싱할 수 없습니다."
                }
                
    except Exception as e:
        print(f"AI 서버 통신 오류: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"AI 서버 통신 실패: {str(e)}"
        )

    # 응답 데이터 처리
    response_text = parsed_data.get("response", "")
    plan_table = parsed_data.get("plan_table", [])
    summary = parsed_data.get("summary", "")
    
    # plan_table 유효성 검사
    validated_plan_table = []
    if isinstance(plan_table, list):
        for i, item in enumerate(plan_table):
            if isinstance(item, dict):
                validated_item = {
                    "time": str(item.get("time", "")),
                    "title": str(item.get("title", f"일정 {i+1}")),
                    "description": str(item.get("description", ""))
                }
                validated_plan_table.append(validated_item)
    
    print(f"최종 결과: response={len(response_text)}, plan_table={len(validated_plan_table)}, summary={len(summary)}")
    
    # 대화 기록에 사용자 메시지와 AI 응답 추가
    conversation_history[current_user.user_id].append(
        {"role": "user", "message": current_message}
    )
    conversation_history[current_user.user_id].append(
        {
            "role": "assistant",
            "message": {
                "response": response_text,
                "summary": summary,
            },
        }
    )
    
    # 계획표 저장
    found_user = None
    for user_info_dict in users:
        if current_user.user_id in user_info_dict:
            found_user = user_info_dict[current_user.user_id]
            break
            
    if found_user and validated_plan_table:
        found_user.plan[today_str] = {
            "plan_table": validated_plan_table,
            "summary": summary,
        }
        print(f"계획표 저장 완료: {today_str}에 {len(validated_plan_table)}개 항목")
    
    print(f"=== AI 채팅 요청 완료 ===\n")
        
    return {
        "response": response_text,
        "plan_table": validated_plan_table,
        "summary": summary,
    }


@app.get('/plan', response_model=List[GetPlanDate])
def get_user_plan(current_user: User=Depends(get_current_user)):
    """
    사용자가 작성한 모든 계획표의 날짜 목록을 반환합니다.
    """
    if not current_user.plan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail='작성된 계획표가 없습니다.')
    
    plan_dates = [GetPlanDate(date=key) for key in current_user.plan.keys()]
    return plan_dates


@app.get('/plan/{date}', response_model=GetPlan)
def get_user_plan_by_date(date: str, current_user:User=Depends(get_current_user)):
    """
    특정 날짜의 계획표 상세 정보를 반환합니다.
    """
    plan = current_user.plan.get(date)
    if plan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail='해당일에 작성된 계획표가 없습니다.')
    
    return GetPlan(date=datetime.strptime(date, "%Y-%m-%d"),
                    plan_table=plan.get('plan_table'),
                    summary=plan.get('summary',''))


@app.put('/plan/{date}', response_model=GetPlan)
def update_plan(new_plan: GetPlan, date: str, current_user: User=Depends(get_current_user)):
    """
    특정 날짜의 계획표를 수정합니다.
    """
    found_user = None
    for user_info_dict in users:
        if current_user.user_id in user_info_dict:
            found_user = user_info_dict[current_user.user_id]
            break
    
    if date in found_user.plan:
        found_user.plan[date] = new_plan.model_dump()
        return new_plan
        
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                        detail='해당일에 작성된 계획표가 없습니다.')


@app.delete('/plan/{date}')
def remove_plan(date: str, current_user: User=Depends(get_current_user)):
    """
    특정 날짜의 계획표를 삭제합니다.
    """
    found_user = None
    for user_info_dict in users:
        if current_user.user_id in user_info_dict:
            found_user = user_info_dict[current_user.user_id]
            break

    if date in found_user.plan:
        found_user.plan.pop(date)
        return {'message': '정상적으로 삭제되었습니다.'}
        
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, 
                        detail='해당일에 작성된 계획표가 없습니다.')


@app.get('/')
async def serve_index():
    """
    'index.html' 파일을 제공합니다.
    """
    return FileResponse('index.html')


@app.get('/api/default-content')
def homepage(current_user: User = Depends(get_current_user)):
    print(f"=== 대시보드 요청 ===")
    print(f"사용자: {current_user.name}")
    
    today_str = datetime.now().strftime("%Y-%m-%d")
    print(f"오늘 날짜: {today_str}")
    print(f"사용자 plan 키들: {list(current_user.plan.keys())}")
    
    # 오늘의 계획표가 있는지 확인
    if today_str not in current_user.plan:
        print("❌ 오늘의 계획표가 없습니다")
        return {'message':'작성된 계획표가 없습니다. 오늘의 계획표를 작성해 보세요'}
    
    plan_data = current_user.plan[today_str]
    print(f"오늘의 계획 데이터: {plan_data}")
    
    plan_table = plan_data.get('plan_table', [])
    print(f"plan_table 길이: {len(plan_table)}")
    
    return plan_table