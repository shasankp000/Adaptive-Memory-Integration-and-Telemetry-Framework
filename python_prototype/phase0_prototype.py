import sys
from random import randint
from typing import List
from copy import deepcopy
from datetime import datetime
from time import sleep
from ctypes import Structure, c_char, c_int32, c_uint32, addressof, sizeof

EPOCH_UPDATE_RULE = 1
MAX_ENTITIES = 2
NAME_LEN = 8

class EntityStruct(Structure):
    _pack_ = 1
    _fields_ = [
        ("name", c_char * NAME_LEN),
        ("x", c_int32),
        ("y", c_int32),
    ]

class EntityRegisterStruct(Structure):
    _pack_ = 1
    _fields_ = [
        ("magic", c_uint32),
        ("version", c_uint32),
        ("tick", c_uint32),
        ("epoch", c_uint32),
        ("count", c_uint32),
        ("entities", EntityStruct * MAX_ENTITIES),
    ]

class EntityLogger:
    def __init__(self):
        self.logger = []

    def log(self, timestamp: float, tick: int, epoch: int, entityRegisterSnapshot: dict) -> None:
        self.logger.append((timestamp, tick, epoch, entityRegisterSnapshot))

    def access_log(self) -> List:
        return self.logger

class Entity:
    def __init__(self, name: str, x: int, y: int):
        self.name = name
        self.x = x
        self.y = y

    def __repr__(self):
        return f"Entity(name={self.name}, x={self.x}, y={self.y})"

    def setx(self, x: int) -> None:
        self.x = x

    def sety(self, y: int) -> None:
        self.y = y

class EntityRegister:
    def __init__(self):
        self.register = {}
        self.shared = EntityRegisterStruct()
        self.shared.magic = 0xA11F
        self.shared.version = 1
        self.shared.tick = 0
        self.shared.epoch = 0
        self.shared.count = MAX_ENTITIES

    def add(self, entity: Entity):
        self.register[entity.name] = entity

    def access_register(self):
        return self.register

    def snapshot(self):
        return deepcopy(self.register)

    def sync_shared(self, tick: int, epoch: int):
        self.shared.tick = tick
        self.shared.epoch = epoch
        for i, entity in enumerate(self.register.values()):
            if i >= MAX_ENTITIES:
                break
            self.shared.entities[i].name = entity.name.encode()[:NAME_LEN-1]
            self.shared.entities[i].x = entity.x
            self.shared.entities[i].y = entity.y

    def shared_address(self):
        return addressof(self.shared)

    def shared_size(self):
        return sizeof(self.shared)

entityRegister = EntityRegister()
entityLogger = EntityLogger()

def gameinit():
    entity1 = Entity("CT1", 0, 0)
    entity2 = Entity("T1", 0, 0)
    entity1.setx(randint(0, 9))
    entity1.sety(randint(0, 9))
    entity2.setx(randint(0, 9))
    entity2.sety(randint(0, 9))
    entityRegister.add(entity1)
    entityRegister.add(entity2)
    entityRegister.sync_shared(0, 0)


def gameloop():
    try:
        second_counter = 0
        current_second = 0
        tick = 0
        epoch = 0
        i = 0
        print(f"PID: {__import__('os').getpid()}")
        print(f"REGISTER_ADDR: {entityRegister.shared_address()}")
        print(f"REGISTER_SIZE: {entityRegister.shared_size()}")
        while i < 220:
            sleep(0.001)
            second_counter += 1
            if second_counter - current_second == 20:
                current_second = second_counter
                tick += 1
                for entity in entityRegister.access_register().values():
                    entity.setx(randint(0, 9))
                    entity.sety(randint(0, 9))
                entityRegister.sync_shared(tick, epoch)
            if tick >= EPOCH_UPDATE_RULE:
                epoch += 1
                entityLogger.log(datetime.now().timestamp(), tick, epoch, entityRegister.snapshot())
                tick = 0
            i += 1
        for entry in entityLogger.access_log():
            print(f"Timestamp: {entry[0]}, Tick: {entry[1]}, Epoch: {entry[2]}, Entity Register: {entry[3]}")
    except KeyboardInterrupt:
        print("Keyboard Interrupt detected, exiting!")
        sys.exit(0)

if __name__ == "__main__":
    gameinit()
    gameloop()
    input("Simulation completed. Press any key to exit...")
