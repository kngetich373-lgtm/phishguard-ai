from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.database import get_db
from app.models import User, Team
from app.schemas import TeamOut, UserCreate, Token, UserOut
from app.auth import hash_password, create_access_token

router = APIRouter(prefix="/api/team", tags=["team"])


@router.get("/me", response_model=TeamOut)
async def my_team(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not current_user.team_id:
        raise HTTPException(status_code=404, detail="You are not part of a team yet")
    result = await db.execute(select(Team).where(Team.id == current_user.team_id))
    team = result.scalar_one()
    await db.refresh(team, attribute_names=["members"])
    return team


@router.post("/invite", response_model=Token)
async def invite_member(
    payload: UserCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not current_user.team_id:
        raise HTTPException(status_code=400, detail="You must belong to a team to invite members")

    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="An account with that email already exists")

    new_member = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        team_id=current_user.team_id,
        is_admin=False,
    )
    db.add(new_member)
    await db.commit()
    await db.refresh(new_member)

    token = create_access_token(subject=new_member.id)
    return Token(access_token=token, user=UserOut.model_validate(new_member))
