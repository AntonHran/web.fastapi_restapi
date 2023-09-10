from typing import List
# from datetime import date

from fastapi import Depends, HTTPException, Path, Query, APIRouter, status
from sqlalchemy.orm import Session

from ht_12.src.database.database_ import get_db
from ht_12.src.repository import contacts as repository_contacts
from ht_12.src.schemes.contacts import ContactModel, ContactResponse
from ht_12.src.database.models_ import User, Role
from ht_12.src.services.auth import auth_user
from ht_12.src.services.roles import RoleAccess


router = APIRouter(prefix="/contacts", tags=["contacts"])

allowed_get = RoleAccess([Role.admin, Role.moderator, Role.user])
allowed_create = RoleAccess([Role.admin, Role.moderator, Role.user])
allowed_update = RoleAccess([Role.admin, Role.moderator])
allowed_remove = RoleAccess([Role.admin])
allowed_search = RoleAccess([Role.admin, Role.moderator, Role.user])
allowed_get_birthdays = RoleAccess([Role.admin, Role.moderator, Role.user])


@router.get("/", response_model=List[ContactResponse],
            dependencies=[Depends(allowed_get)],
            description="For all")
async def get_contacts(
        limit: int = Query(10, le=100),
        offset: int = 0,
        db: Session = Depends(get_db),
        current_user: User = Depends(auth_user.get_current_user)
):
    contacts = await repository_contacts.get_all(limit, offset, current_user, db)
    return contacts


@router.get("/{contact_id}", response_model=ContactResponse,
            dependencies=[Depends(allowed_get)],
            description="For all"
            )
async def get_contact(contact_id: int = Path(ge=1),
                      current_user: User = Depends(auth_user.get_current_user),
                      db: Session = Depends(get_db)):
    contact = await repository_contacts.get_contact_by_id(contact_id, current_user, db)
    if not contact:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    return contact


@router.post("/", response_model=ContactResponse,
             status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(allowed_create)],
             description="For all"
             )
async def create_contact(body: ContactModel,
                         current_user: User = Depends(auth_user.get_current_user),
                         db: Session = Depends(get_db)):
    contact = await repository_contacts.create_contact(body, current_user, db)
    if contact is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Such contact already exists")
    return contact


@router.put("/{contact_id}", response_model=ContactResponse,
            dependencies=[Depends(allowed_update)],
            description="For moderators and admin"
            )
async def update_contact(
        body: ContactModel,
        contact_id: int = Path(ge=1),
        current_user: User = Depends(auth_user.get_current_user),
        db: Session = Depends(get_db)
):
    contact = await repository_contacts.update(contact_id, body, current_user, db)
    if not contact:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    return contact


@router.delete("/{contact_id}", status_code=status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(allowed_remove)],
               description="For admin only"
               )
async def delete_contact(contact_id: int = Path(ge=1),
                         current_user: User = Depends(auth_user.get_current_user),
                         db: Session = Depends(get_db)):
    contact = await repository_contacts.remove(contact_id, current_user, db)
    if not contact:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    return contact


@router.get("/search/", response_model=List[ContactResponse],
            dependencies=[Depends(allowed_search)],
            description="For all"
            )
async def search_by(parameter: str | int,
                    current_user: User = Depends(auth_user.get_current_user),
                    db: Session = Depends(get_db)):
    contacts = await repository_contacts.search(parameter, current_user, db)
    if not contacts:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    return contacts


@router.get("/birthdays/", response_model=List[ContactResponse],
            dependencies=[Depends(allowed_get_birthdays)],
            description="For all"
            )
async def get_birthdays(current_user: User = Depends(auth_user.get_current_user),
                        db: Session = Depends(get_db)):
    contacts = await repository_contacts.birthdays(current_user, db)
    if not contacts:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    return contacts
