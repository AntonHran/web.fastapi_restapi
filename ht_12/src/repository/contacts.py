from datetime import date, timedelta
import logging

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from ht_12.src.database.models_ import Contact, User, UserToContact
from ht_12.src.schemes.contacts import ContactModel

logger = logging.getLogger(__name__)


async def get_contact_ids(user: User, db: Session) -> list[int]:
    # contact_ids = db.query(UserToContact).filter_by(user_id=user.id).all()
    contact_ids = db.query(UserToContact.contact_id).filter_by(user_id=user.id).all()
    return [cont.contact_id for cont in contact_ids]


async def get_all(limit: int, offset: int, user: User, db: Session):
    contact_ids = await get_contact_ids(user, db)
    contacts: list = (
        db.query(Contact)
        .filter(Contact.id.in_(contact_ids))
        .limit(limit)
        .offset(offset)
        .all()
    )
    return contacts


async def get_contact_by_id(contact_id: int, user: User, db: Session):
    contact_ids = await get_contact_ids(user, db)
    if contact_id in contact_ids:
        contact = db.query(Contact).filter_by(id=contact_id).first()
        return contact


async def create_record(contact_id: int, user: User, db: Session):
    record = UserToContact(user_id=user.id, contact_id=contact_id)
    db.add(record)
    db.commit()
    db.refresh(record)


async def create_contact(body: ContactModel, user: User, db: Session):
    contact = Contact(**body.model_dump())
    try:
        db.add(contact)
        db.commit()
        db.refresh(contact)
        await create_record(contact.id, user, db)
        return contact
    except IntegrityError as err:
        db.rollback()
        print(err)
        await check(contact, user, db)


async def check(contact: Contact, user: User, db):
    existing_contact = (
        db.query(Contact).filter_by(phone_number=contact.phone_number).first()
    )
    user_contacts = db.query(UserToContact.contact_id).filter_by(user_id=user.id).all()
    if existing_contact and existing_contact.id not in [cont.contact_id for cont in user_contacts]:
        await create_record(existing_contact.id, user, db)


async def update(contact_id: int, body: ContactModel, user: User, db: Session):
    contact = await get_contact_by_id(contact_id, user, db)
    if contact:
        contact.first_name = body.first_name
        contact.last_name = body.last_name
        contact.phone_number = body.phone_number
        contact.email = body.email
        contact.birth_date = body.birth_date
        contact.notes = body.notes
        db.commit()
        db.refresh(contact)
    return contact


async def remove(contact_id: int, user: User, db: Session):
    contact = await get_contact_by_id(contact_id, user, db)
    if contact:
        db.delete(contact)
        db.commit()
    return contact


async def search(parameter: str | int, user: User, db: Session):
    attributes: list[str] = list(vars(Contact).keys())
    result = []
    contact_ids = await get_contact_ids(user, db)
    for attribute in attributes:
        try:
            query = (
                db.query(Contact)
                .filter(
                    Contact.id.in_(contact_ids),
                    getattr(Contact, attribute).ilike("%" + parameter + "%")
                    if attribute != "id"
                    else None,
                )
                .all()
            )
        except Exception as error:
            logger.error(f"Error during proceeding SQL-query: {str(error)}")
            continue
        if query:
            result.extend([rec for rec in query if rec not in result])
    return result


async def birthdays(user: User, db: Session):
    current_date = date.today()
    dates: list = [current_date + timedelta(days=i) for i in range(7)]
    result = []
    contacts = [
        contact
        for contact in await get_all(limit=100, offset=0, user=user, db=db)
        if contact.birth_date
    ]
    for contact in contacts:
        b_date = date(
            year=current_date.year,
            month=contact.birth_date.month,
            day=contact.birth_date.day,
        )
        if b_date in dates:
            result.append(contact)
    return result
