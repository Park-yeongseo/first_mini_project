# models.py

from datetime import datetime, time, timedelta
import re
from typing import List, Optional
import uuid
from fastapi import HTTPException, status
from pydantic import BaseModel, Field, field_validator

from datas.users import users


class Routine(BaseModel):
    """
    루틴 정보를 나타내는 Pydantic 모델
    """
    routine_id: str = None
    title: str
    routine_time: Optional[time] = None
    time_taken_minutes: Optional[timedelta] = None
    time_zone: Optional[str] = None

    @field_validator("title")
    @classmethod
    def validate_title(cls, title: str):
        """
        타이틀 필드 유효성 검사
        - 공백 제거 후 2자 이상인지 확인
        """
        title = title.strip()
        if not title:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="입력되지 않았습니다."
            )
        if len(title) < 2:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="타이틀은 3자 이상이어야 합니다.",
            )
        return title


class UpdateRoutine(BaseModel):
    """
    루틴 수정에 사용되는 Pydantic 모델
    """
    title: str
    routine_time: Optional[time] = None
    time_taken_minutes: Optional[timedelta] = None
    time_zone: Optional[str] = None

    @field_validator("title")
    @classmethod
    def validate_title(cls, title: str):
        """
        타이틀 필드 유효성 검사
        - 공백 제거 후 2자 이상인지 확인
        """
        title = title.strip()
        if not title:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="입력되지 않았습니다."
            )
        if len(title) < 2:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="타이틀은 3자 이상이어야 합니다.",
            )
        return title


class CreateRoutine(Routine):
    """
    새 루틴 생성에 사용되는 Pydantic 모델
    - 각 요일별 루틴 추가 여부를 나타내는 bool 필드 포함
    """
    monday: bool = False
    tuesday: bool = False
    wednesday: bool = False
    thursday: bool = False
    friday: bool = False
    saturday: bool = False
    sunday: bool = False


class RoutineTitle(BaseModel):
    """
    루틴 제목만 포함하는 간단한 모델
    """
    title: str


class RoutineList(BaseModel):
    """
    요일별 루틴 목록을 담는 모델
    """
    monday: List[Routine] = []
    tuesday: List[Routine] = []
    wednesday: List[Routine] = []
    thursday: List[Routine] = []
    friday: List[Routine] = []
    saturday: List[Routine] = []
    sunday: List[Routine] = []


class RoutineTitleList(BaseModel):
    """
    요일별 루틴 제목 목록을 담는 모델 (타이틀만 보여줄 때 사용)
    """
    monday: List[RoutineTitle] | None = None
    tuesday: List[RoutineTitle] | None = None
    wednesday: List[RoutineTitle] | None = None
    thursday: List[RoutineTitle] | None = None
    friday: List[RoutineTitle] | None = None
    saturday: List[RoutineTitle] | None = None
    sunday: List[RoutineTitle] | None = None


class User(BaseModel):
    """
    사용자 정보를 나타내는 Pydantic 모델
    """
    login_id: str
    name: str
    password: str
    age: int
    email: str
    user_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: Optional[datetime] = datetime.now()
    routine: RoutineList
    plan: Optional[dict] = {}

    @field_validator("login_id")
    @classmethod
    def validate_user_id(cls, login_id: str):
        """
        로그인 ID 유효성 검사
        - 5자 이상인지, 이미 사용 중인 ID인지 확인
        """
        login_id = login_id.strip()
        if not login_id or len(login_id) < 5:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="로그인 아이디는 5자 이상이어야 합니다.",
            )
        for user_info_dict in users:
            for v in user_info_dict.values():
                if v.login_id == login_id:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="이미 사용중인 아이디 입니다.",
                    )
        return login_id

    @field_validator("name")
    @classmethod
    def validate_name(cls, name: str):
        """
        이름 유효성 검사
        - 공백 제거 후 2자 이상인지, 알파벳으로만 구성되었는지 확인
        """
        name = name.strip()
        if not name:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="성함을 입력해 주세요"
            )
        if len(name) < 2:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="이름은 두자 이상이어야 합니다.",
            )
        if not name.isalpha():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="잘못된 이름 형식 입니다.",
            )
        return name

    @field_validator("age")
    @classmethod
    def validate_age(cls, age: int):
        """
        나이 유효성 검사
        - 0 이상인지 확인
        """
        if age < 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="나이는 0살 이상이어야 합니다.",
            )
        return age

    @field_validator("email")
    @classmethod
    def validate_email(cls, email: str):
        """
        이메일 유효성 검사
        - 정규식을 사용하여 형식 확인
        """
        email_regex = r"^[A-Za-z0-9]+([._-][A-Za-z0-9]+)*@[A-Za-z0-9-]+\.[A-Za-z]{2,}$"
        if not re.match(email_regex, email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="잘못된 이메일 형식입니다.",
            )
        return email

    @field_validator("password")
    @classmethod
    def validate_password(cls, password: str):
        """
        비밀번호 유효성 검사
        - 8자 이상인지, 특수문자를 포함하는지 확인
        """
        if len(password) < 8:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="비밀번호는 8자 이상이어야 합니다.",
            )
        # 비밀번호에 알파벳과 숫자가 아닌 문자가 1개 이상 있는지 확인
        if password.isalnum():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="특수문자를 1개 이상 포함해 주세요",
            )
        return password


class UserLogin(BaseModel):
    """
    사용자 로그인 요청을 위한 모델
    """
    login_id: str
    password: str


class Token(BaseModel):
    """
    JWT 토큰 응답을 위한 모델
    """
    access_token: str
    token_type: str


class UserUpdate(BaseModel):
    """
    사용자 정보 업데이트 요청을 위한 모델
    - 모든 필드가 Optional
    """
    name: Optional[str] = None
    password: Optional[str] = None
    age: Optional[int] = None
    email: Optional[str] = None

    # 유효성 검사는 User 모델과 동일
    @field_validator("name")
    @classmethod
    def validate_name(cls, name: str):
        name = name.strip()
        if not name:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="성함을 입력해 주세요"
            )
        if len(name) < 2:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="이름은 두자 이상이어야 합니다.",
            )
        if not name.isalpha():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="잘못된 이름 형식 입니다.",
            )
        return name

    @field_validator("age")
    @classmethod
    def validate_age(cls, age: int):
        if age < 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="나이는 0살 이상이어야 합니다.",
            )
        return age

    @field_validator("email")
    @classmethod
    def validate_email(cls, email: str):
        email_regex = r"^[A-Za-z0-9]+([._-][A-Za-z0-9]+)*@[A-Za-z0-9-]+\.[A-Za-z]{2,}$"
        if not re.match(email_regex, email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="잘못된 이메일 형식입니다.",
            )
        return email

    @field_validator("password")
    @classmethod
    def validate_password(cls, password: str):
        if len(password) < 8:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="비밀번호는 8자 이상이어야 합니다.",
            )
        if password.isalnum():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="특수문자를 1개 이상 포함해 주세요",
            )
        return password


class UserResponse(BaseModel):
    """
    사용자 정보 응답을 위한 모델 (민감 정보 제외)
    """
    login_id: str
    name: str
    age: int
    email: str
    user_id: str
    created_at: datetime
    routine: Optional[RoutineList]
    plan: Optional[dict]


class DecisionUpdate(BaseModel):
    """
    비밀번호 확인 요청을 위한 모델
    """
    password: str


class TaskItem(BaseModel):
    """
    챗봇에게 요청할 작업 항목 모델
    """
    title: str  # 필수
    expected_duration: Optional[int] = None  # 예상 소요 시간
    target_start_time: Optional[time] = None  # 목표 시작 시간
    additional_info: Optional[str] = None  # 추가 정보 (예: 약속 장소, 주의사항 등)


class ChatRequest(BaseModel):
    """
    챗봇 요청을 위한 모델
    """
    tasks: List[TaskItem]
    message: Optional[str] = None


class ChatResponse(BaseModel):
    """
    챗봇 응답을 위한 모델
    """
    response: str
    plan_table: List[dict] | None = None
    summary: str | None = None


class GetPlan(BaseModel):
    """
    계획표 상세 정보를 가져오기 위한 모델
    """
    date: datetime
    plan_table: List[dict]
    summary: Optional[str] = None


class GetPlanDate(BaseModel):
    """
    계획표 날짜 정보를 가져오기 위한 모델
    """
    date: str