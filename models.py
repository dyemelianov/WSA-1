import datetime
from pytz import timezone, utc
from datetime import datetime, timedelta
from sqlalchemy.sql import func
from sqlalchemy import create_engine, Column, Integer, inspect, Unicode, UnicodeText, Date, DateTime, desc, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import logging

import settings
from singleton_decorator import SingletonDecorator

DeclarativeBase = declarative_base()


def db_connect():
    """Performs database connection using database settings from settings.py.
    Returns sqlalchemy engine instance.
    """
    connection_str = 'mysql+mysqldb://{}:{}@{}:{}/{}?charset=utf8&use_unicode=1'.format(settings.DB_USERNAME,
                                                                                        settings.DB_PASSWORD,
                                                                                        settings.DB_HOST,
                                                                                        settings.DB_PORT,
                                                                                        settings.DB_NAME)
    return create_engine(connection_str)


def create_tables(engine):
    """"""
    DeclarativeBase.metadata.create_all(engine)


def to_dict(obj, with_relationships=True):
    d = {}
    for column in obj.__table__.columns:
        if with_relationships and len(column.foreign_keys) > 0:
            # Skip foreign keys
            continue
        d[column.name] = getattr(obj, column.name)

    if with_relationships:
        for relationship in inspect(type(obj)).relationships:
            val = getattr(obj, relationship.key)
            d[relationship.key] = to_dict(val) if val else None
    return d


class QueueModel(DeclarativeBase):
    """Sqlalchemy update queue model"""
    __tablename__ = "queue"
    __table_args__ = {
        'mysql_charset': 'utf8'
    }

    def __init__(self, **kwargs):
        cls_ = type(self)
        for k in kwargs:
            if hasattr(cls_, k):
                setattr(self, k, kwargs[k])

    id = Column(Integer, primary_key=True)
    call_id = Column(Integer)
    call_type = Column(Unicode(20))
    agent_group = Column(Unicode(255))
    inserted_on = Column(DateTime, server_default=func.now())
    updated_on = Column(DateTime, server_onupdate=func.now())
    state = Column(Unicode(20))


class LoginModel(DeclarativeBase):
    """Sqlalchemy update login model"""
    __tablename__ = "login"
    __table_args__ = {
        'mysql_charset': 'utf8'
    }

    def __init__(self, **kwargs):
        cls_ = type(self)
        for k in kwargs:
            if hasattr(cls_, k):
                setattr(self, k, kwargs[k])

    id = Column(Integer, primary_key=True)
    agent_group = Column(Unicode(255))
    logged_in = Column(DateTime, server_default=func.now())
    logged_out = Column(DateTime)


class ReportModel(DeclarativeBase):
    """Sqlalchemy deals model"""
    __tablename__ = "report"
    __table_args__ = {
        'mysql_charset': 'utf8'
    }

    def __init__(self, **kwargs):
        cls_ = type(self)
        for k in kwargs:
            if hasattr(cls_, k):
                setattr(self, k, kwargs[k])

    id = Column(Integer, primary_key=True)
    call_id = Column(Integer)
    call_date = Column(Date)
    name = Column(Unicode(255))
    call_campaign = Column(Unicode(255))
    direction = Column(Unicode(20))
    duration = Column(Unicode(50))
    call_type = Column(Unicode(20))
    call_memo = Column(UnicodeText)
    call_reason_id = Column(Integer, default=None)
    call_reason = Column(UnicodeText)
    call_time = Column(Unicode(20))
    caller_phone = Column(Unicode(20))
    call_from = Column(Unicode(20))
    call_to = Column(Unicode(20))
    agent_id = Column(Integer, default=None)
    agent_name = Column(Unicode(255))
    agent_group = Column(Unicode(255))
    job_id = Column(Integer, default=None)
    job_type = Column(Unicode(100))
    customer_name = Column(Unicode(100))
    status = Column(Unicode(100))
    record_path = Column(UnicodeText)
    user_name = Column(Unicode(255))
    user_pass = Column(Unicode(255))
    report_type = Column(Integer)
    report_id = Column(Integer, default=None)
    blocked_id = Column(Integer, default=None)
    url = Column(Unicode(255))
    record_found = Column(Integer, default=None)
    inserted_on = Column(DateTime, server_default=func.now())


@SingletonDecorator
class DbHandler:
    def __init__(self):
        engine = db_connect()
        engine.execution_options(stream_results=True)
        create_tables(engine)
        self.Session = sessionmaker(bind=engine)

    def add_login(self, data: dict):
        mdl_id = None
        session = None
        try:
            session = self.Session()
            mdl = LoginModel(**data)
            session.add(mdl)
            session.commit()
            mdl_id = mdl.id
        except Exception as x:
            logging.exception("Exception occurred: %s", x)
        finally:
            if session:
                session.close()
        return mdl_id

    def add_queue(self, data: dict):
        session = None
        try:
            session = self.Session()
            data["state"] = 'New'
            mdl = QueueModel(**data)
            session.add(mdl)
            session.commit()
        except Exception as x:
            logging.exception("Exception occurred: %s", x)
        finally:
            if session:
                session.close()

    def add_report(self, data: dict):
        session = None
        try:
            session = self.Session()
            mdl = ReportModel(**data)
            session.add(mdl)
            session.commit()
        except Exception as x:
            logging.exception("Exception occurred: %s", x)
        finally:
            if session:
                session.close()

    def update_login(self, data: dict):
        session = None
        try:
            session = self.Session()
            mdl = LoginModel(**data)
            session.add(mdl)
            session.commit()
        except Exception as x:
            logging.exception("Exception occurred: %s", x)
        finally:
            if session:
                session.close()

    def update_queue(self, data: dict):
        session = None
        try:
            session = self.Session()
            mdl = QueueModel(**data)
            session.add(mdl)
            session.commit()
        except Exception as x:
            logging.exception("Exception occurred: %s", x)
        finally:
            if session:
                session.close()

    def update_report(self, data: dict):
        session = None
        try:
            session = self.Session()
            mdl = ReportModel(**data)
            session.add(mdl)
            session.commit()
        except Exception as x:
            logging.exception("Exception occurred: %s", x)
        finally:
            if session:
                session.close()

    def search_login(self, query: dict, timespan):
        since = datetime.now() - timedelta(seconds=timespan)
        logging.info("Since: %s", since)
        session = None
        try:
            session = self.Session()
            q_data = session.query(LoginModel).filter_by(**query).filter(LoginModel.logged_in > since) \
                .order_by(LoginModel.logged_in.desc()).count()
            if q_data:
                return q_data
        except Exception as x:
            logging.exception("Exception occurred: %s", x)
        finally:
            if session:
                session.close()

    def search_queue(self, query: dict):
        session = None
        try:
            session = self.Session()
            q_data = session.query(QueueModel).filter_by(**query)
            if q_data:
                return q_data
        except Exception as x:
            logging.exception("Exception occurred: %s", x)
        finally:
            if session:
                session.close()

    def search_report(self, query: dict):
        session = None
        try:
            session = self.Session()
            q_data = session.query(ReportModel).filter_by(**query).first()
            if q_data:
                return q_data
        except Exception as x:
            logging.exception("Exception occurred: %s", x)
        finally:
            if session:
                session.close()

    def update_queue_by_id(self, q_id: int, model_data: dict):
        session = None
        err = ''
        try:
            session = self.Session()
            q = {'id': q_id}
            data = session.query(QueueModel).filter_by(**q).first()
            if data:
                for k in model_data.keys():
                    if 'call_type' in k:
                        data.call_type = model_data['call_type']
                    if 'agent_group' in k:
                        data.agent_group = model_data['agent_group']
                    if 'state' in k:
                        logging.info("State: %s", model_data['state'])
                        data.state = model_data['state']
                session.commit()
                return {'status': True, 'message': 'SUCCESS!'}
            else:
                return {'status': False, 'message': 'NO RECORD FOUND!'}
        except Exception as x:
            logging.exception("Exception occurred: %s", x)
        finally:
            if session:
                session.close()
        return {'status': False, 'message': err}

    def update_report_by_id(self, id: int, model_data: dict):
        session = None
        err = ''
        try:
            session = self.Session()
            q = {'call_id': id}
            data = session.query(ReportModel).filter_by(**q).first()
            if data:
                for k in model_data.keys():
                    if 'name' in k:
                        data.name = model_data['name']
                    if 'call_campaign' in k:
                        data.call_campaign = model_data['call_campaign']
                    if 'call_date' in k:
                        data.call_date = model_data['call_date']
                    if 'call_memo' in k:
                        data.call_memo = model_data['call_memo']
                    if 'call_reason' in k:
                        data.call_reason = model_data['call_reason']
                    if 'call_time' in k:
                        data.call_time = model_data['call_time']
                    if 'call_type' in k:
                        data.call_type = model_data['call_type']
                    if 'customer_name' in k:
                        data.customer_name = model_data['customer_name']
                    if 'direction' in k:
                        data.direction = model_data['direction']
                    if 'duration' in k:
                        data.duration = model_data['duration']
                    if 'job_id' in k and model_data[k] is not None and model_data[k] is int:
                        data.job_id = model_data['job_id']
                    if 'job_type' in k:
                        data.job_type = model_data['job_type']
                    if 'record_found' in k:
                        data.record_found = model_data['record_found']

                session.commit()
                return {'status': True, 'message': 'SUCCESS!'}
            else:
                return {'status': False, 'message': 'NO RECORD FOUND!'}
        except Exception as x:
            logging.exception("Exception occurred: %s", x)
        finally:
            if session:
                session.close()
        return {'status': False, 'message': err}

    def delete_report(self, query: dict):
        session = None
        try:
            session = self.Session()
            q_data = session.query(ReportModel).filter_by(**query).first()
            if q_data:
                session.delete(q_data)
        except Exception as x:
            logging.exception("Exception occurred: %s", x)
        finally:
            if session:
                session.close()
