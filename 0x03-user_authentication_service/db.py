#!/usr/bin/env python3
"""Database module containing the DB class for user management.
"""

from sqlalchemy import create_engine, tuple_
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm.session import Session

from user import Base, User

class DB:
    """Database management class for user operations.
    """

    def __init__(self) -> None:
        """Initialize a new DB instance with an SQLite database.
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        # Drop and create all tables in the database.
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object for database interactions.
        """
        # Create a new session if it doesn't exist.
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Add a new user to the database.
        """
        try:
            new_user = User(email=email, hashed_password=hashed_password)
            self._session.add(new_user)
            self._session.commit()
        except Exception:
            # Rollback changes in case of an exception.
            self._session.rollback()
            new_user = None
        return new_user

    def find_user_by(self, **kwargs) -> User:
        """Find a user based on a set of specified filters.
        """
        fields, values = [], []
        for key, value in kwargs.items():
            # Check if the attribute exists in the User model.
            if hasattr(User, key):
                fields.append(getattr(User, key))
                values.append(value)
            else:
                raise InvalidRequestError()
        result = self._session.query(User).filter(
            tuple_(*fields).in_([tuple(values)])
        ).first()
        if result is None:
            raise NoResultFound()
        return result

    def update_user(self, user_id: int, **kwargs) -> None:
        """Update a user based on the given user ID.
        """
        # Find the user with the specified ID.
        user = self.find_user_by(id=user_id)
        if user is None:
            return
        # Prepare the fields and values for updating.
        update_source = {}
        for key, value in kwargs.items():
            if hasattr(User, key):
                update_source[getattr(User, key)] = value
            else:
                raise ValueError()
        # Update the user information in the database.
        self._session.query(User).filter(User.id == user_id).update(
            update_source,
            synchronize_session=False,
        )
        self._session.commit()

