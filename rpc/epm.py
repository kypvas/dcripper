import struct
from typing import Optional, Tuple
from rpc.dcerpc import DCERPCClient
from rpc.ndr import NDRSerializer, NDRDeserializer
from transport.tcp import TCPTransport

class EndpointMapper:
    EPM_UUID = bytes.fromhex("e1af83085d1f11c991a408002b14a0fa")
    EPM_VERSION = (3, 0)
    
    EPM_MAP = 3
    
    def __init__(self, host: str, timeout: int = 30):
        self.host = host
        self.timeout = timeout
        
    def map_endpoint(self, interface_uuid: bytes, version: Tuple[int, int]) -> int:
        transport = TCPTransport(self.host, 135, self.timeout)
        transport.connect()
        
        try:
            client = DCERPCClient(transport)
            client.bind(self.EPM_UUID, self.EPM_VERSION)
            
            request = self._build_map_request(interface_uuid, version)
            response = client.call(self.EPM_MAP, request)
            
            port = self._parse_map_response(response)
            return port
        finally:
            transport.disconnect()
    
    def _build_map_request(self, interface_uuid: bytes, version: Tuple[int, int]) -> bytes:
        tower = self._build_tower(interface_uuid, version)
        
        ndr = NDRSerializer()
        
        ndr.pack_uint32(1)
        ndr.pack_bytes(bytes(16))
        
        ndr.pack_uint32(2)
        ndr.pack_uint32(len(tower))
        ndr.pack_uint32(len(tower))
        ndr.pack_bytes(tower)
        ndr.align(4)
        
        ndr.pack_bytes(bytes(20))
        ndr.pack_uint32(4)
        
        return ndr.get_data()
    
    def _build_tower(self, interface_uuid: bytes, version: Tuple[int, int]) -> bytes:
        floors = []
        
        uuid_le = (
            interface_uuid[0:4][::-1] +
            interface_uuid[4:6][::-1] +
            interface_uuid[6:8][::-1] +
            interface_uuid[8:16]
        )
        floor1 = bytearray()
        floor1.extend(struct.pack("<H", 19))
        floor1.append(0x0d)
        floor1.extend(uuid_le)
        floor1.extend(struct.pack("<H", version[0]))
        floor1.extend(struct.pack("<H", 2))
        floor1.extend(struct.pack("<H", version[1]))
        floors.append(bytes(floor1))
        
        ndr_uuid = bytes.fromhex("8a885d041ceb11c99fe808002b104860")
        ndr_le = (
            ndr_uuid[0:4][::-1] +
            ndr_uuid[4:6][::-1] +
            ndr_uuid[6:8][::-1] +
            ndr_uuid[8:16]
        )
        floor2 = bytearray()
        floor2.extend(struct.pack("<H", 19))
        floor2.append(0x0d)
        floor2.extend(ndr_le)
        floor2.extend(struct.pack("<H", 2))
        floor2.extend(struct.pack("<H", 2))
        floor2.extend(struct.pack("<H", 0))
        floors.append(bytes(floor2))
        
        floor3 = struct.pack("<H", 1) + b"\x0b" + struct.pack("<H", 2) + struct.pack("<H", 0)
        floors.append(floor3)
        
        floor4 = struct.pack("<H", 1) + b"\x07" + struct.pack("<H", 2) + struct.pack(">H", 0)
        floors.append(floor4)
        
        floor5 = struct.pack("<H", 1) + b"\x09" + struct.pack("<H", 4) + bytes(4)
        floors.append(floor5)
        
        tower = bytearray()
        tower.extend(struct.pack("<H", len(floors)))
        for floor in floors:
            tower.extend(floor)
        
        return bytes(tower)
    
    def _parse_map_response(self, response: bytes) -> int:
        ndr = NDRDeserializer(response)

        entry_handle = ndr.unpack_bytes(20)
        num_towers = ndr.unpack_uint32()

        if num_towers == 0:
            raise Exception("No endpoint found")

        # ITowers is NDRUniConformantVaryingArray
        max_count = ndr.unpack_uint32()
        offset = ndr.unpack_uint32()
        actual_count = ndr.unpack_uint32()

        # Read all tower pointers first (referent IDs)
        tower_ptrs = []
        for i in range(actual_count):
            tower_ptrs.append(ndr.unpack_uint32())

        if tower_ptrs[0] == 0:
            raise Exception("Null tower pointer")

        # Now read deferred tower data for first tower
        # twr_t structure: tower_length (ULONG) + tower_octet_string (NDRUniConformantArray)
        tower_len = ndr.unpack_uint32()

        # NDRUniConformantArray has max_count prefix
        tower_max_count = ndr.unpack_uint32()

        # Now read the actual tower data
        num_floors = ndr.unpack_uint16()

        for i in range(num_floors):
            lhs_len = ndr.unpack_uint16()
            protocol_id = ndr.unpack_uint8()
            lhs_data = ndr.unpack_bytes(lhs_len - 1)

            rhs_len = ndr.unpack_uint16()
            rhs_data = ndr.unpack_bytes(rhs_len)

            if protocol_id == 0x07 and rhs_len == 2:
                port = struct.unpack(">H", rhs_data)[0]
                return port

        raise Exception("Could not find TCP port in tower")
