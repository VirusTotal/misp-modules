import json
from .utils.utils import query_get_module
from . import db
from .db_class.db import History, Module, Config, Module_Config, Session_db


def get_module(mid):
    return Module.query.get(mid)

def get_module_by_name(name):
    return Module.query.filter_by(name=name).first()

def get_config(cid):
    return Config.query.get(cid)

def get_config_by_name(name):
    return Config.query.filter_by(name=name).first()

def get_module_config_module(mid):
    return Module_Config.query.filter_by(module_id=mid).all()

def get_module_config_both(mid, cid):
    return Module_Config.query.filter_by(module_id=mid, config_id=cid).first()

def get_session(sid):
    return Session_db.query.filter_by(uuid=sid).first()

def get_modules(expansion, hover):
    res = query_get_module()
    if not "message" in res:
        loc_list = dict()
        loc_list["expansion"] = list()
        loc_list["hover"] = list()
        for module in res:
            module_db = get_module_by_name(module["name"])
            module_loc = module
            module_loc["request_on_query"] = module_db.request_on_query
            if module_db.is_active:
                if expansion:
                    if "expansion" in module["meta"]["module-type"]:
                        loc_list["expansion"].append(module_loc)
                if hover:
                    if "hover" in module["meta"]["module-type"]:
                        loc_list["hover"].append(module_loc)
        loc_list["expansion"].sort(key=lambda x: x["name"])
        loc_list["hover"].sort(key=lambda x: x["name"])
        return loc_list
    return res


def util_get_attr(module, loc_list):
    if "input" in module["mispattributes"]:
        for input in module["mispattributes"]["input"]:
            if not input in loc_list:
                loc_list.append(input)
    return loc_list

def get_list_misp_attributes(expansion, hover):
    res = query_get_module()
    if not "message" in res:
        loc_list = list()

        for module in res:
            if get_module_by_name(module["name"]).is_active:
                if expansion:
                    if "expansion" in module["meta"]["module-type"]:
                        loc_list = util_get_attr(module, loc_list)
                if hover:
                    if "hover" in module["meta"]["module-type"]:
                        loc_list = util_get_attr(module, loc_list)
        loc_list.sort()
        return loc_list
    return res


def get_modules_config():
    modules = Module.query.order_by(Module.name).all()
    modules_list = []
    for module in modules:
        loc_module = module.to_json()
        loc_module["config"] = []
        mcs = Module_Config.query.filter_by(module_id=module.id).all()
        for mc in mcs:
            conf = Config.query.get(mc.config_id)
            loc_module["config"].append({conf.name: mc.value})
        modules_list.append(loc_module)
    return modules_list


def change_config_core(request_json):
    module = get_module_by_name(request_json["module_name"])
    for element in request_json:
        if not element == "module_name":
            config = get_config_by_name(element)
            if config:
                m_c = get_module_config_both(module.id, config.id)
                m_c.value = request_json[element]
                db.session.commit()
    module.request_on_query = request_json["request_on_query"]
    db.session.commit()
    return True

def change_status_core(module_id):
    module = get_module(module_id)
    module.is_active = not module.is_active
    db.session.commit()
    return True



def get_status_db(session):
    glob_query = json.loads(session.glob_query)
    result = json.loads(session.result)
    return{
        'id': session.uuid,
        'total': len(glob_query),
        'complete': len(glob_query),
        'remaining': 0,
        'registered': len(result),
        'stopped' : True,
        "nb_errors": session.nb_errors
    }

def get_result_db(session):
    return json.loads(session.result)

def get_history():
    histories_list = list()
    histories = History.query.all()
    for history in histories:
        session = Session_db.query.get(history.session_id)
        histories_list.append({"uuid": session.uuid, "query": session.query_enter, "modules": json.loads(session.glob_query), "input": session.input_query})
    return histories_list