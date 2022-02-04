export const DIDDocABI = {
    "ABI version": 2,
    "version": "2.2",
    "header": [
        "pubkey",
        "time",
        "expire"
    ],
    "functions": [
        {
            "name": "constructor",
            "inputs": [
                {
                    "name": "pubKey",
                    "type": "uint256"
                },
                {
                    "name": "didDocument",
                    "type": "string"
                }
            ],
            "outputs": []
        },
        {
            "name": "init",
            "inputs": [
                {
                    "name": "issuerAddr",
                    "type": "address"
                }
            ],
            "outputs": []
        },
        {
            "name": "newDidDocument",
            "inputs": [
                {
                    "name": "didDocument",
                    "type": "string"
                }
            ],
            "outputs": []
        },
        {
            "name": "newDidStatus",
            "inputs": [
                {
                    "name": "status",
                    "type": "uint8"
                }
            ],
            "outputs": []
        },
        {
            "name": "newDidIssuerAddr",
            "inputs": [
                {
                    "name": "issuerAddr",
                    "type": "address"
                }
            ],
            "outputs": []
        },
        {
            "name": "deleteDidDocument",
            "inputs": [],
            "outputs": []
        },
        {
            "name": "getDid",
            "inputs": [],
            "outputs": [
                {
                    "components": [
                        {
                            "name": "status",
                            "type": "uint8"
                        },
                        {
                            "name": "PubKey",
                            "type": "uint256"
                        },
                        {
                            "name": "issuerAddr",
                            "type": "address"
                        },
                        {
                            "name": "didDocument",
                            "type": "string"
                        }
                    ],
                    "name": "value0",
                    "type": "tuple"
                }
            ]
        },
        {
            "name": "getInfo",
            "inputs": [],
            "outputs": [
                {
                    "name": "addrDidStorage",
                    "type": "address"
                },
                {
                    "components": [
                        {
                            "name": "status",
                            "type": "uint8"
                        },
                        {
                            "name": "PubKey",
                            "type": "uint256"
                        },
                        {
                            "name": "issuerAddr",
                            "type": "address"
                        },
                        {
                            "name": "didDocument",
                            "type": "string"
                        }
                    ],
                    "name": "didItem",
                    "type": "tuple"
                }
            ]
        }
    ],
    "data": [
        {
            "key": 1,
            "name": "_id",
            "type": "uint256"
        }
    ],
    "events": [],
    "fields": [
        {
            "name": "_pubkey",
            "type": "uint256"
        },
        {
            "name": "_timestamp",
            "type": "uint64"
        },
        {
            "name": "_constructorFlag",
            "type": "bool"
        },
        {
            "components": [
                {
                    "name": "status",
                    "type": "uint8"
                },
                {
                    "name": "PubKey",
                    "type": "uint256"
                },
                {
                    "name": "issuerAddr",
                    "type": "address"
                },
                {
                    "name": "didDocument",
                    "type": "string"
                }
            ],
            "name": "_didItem",
            "type": "tuple"
        },
        {
            "name": "_addrDidStorage",
            "type": "address"
        },
        {
            "name": "_id",
            "type": "uint256"
        }
    ]
}