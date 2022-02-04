import {signerNone, TonClient} from '@tonclient/core';
import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import {libNode} from '@tonclient/lib-node';
import {DIDStorageABI} from '../tools/DIDStorageABI';
import {DIDDocABI} from '../tools/DIDDocABI';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateUserDto } from './dto/createUser.dto';
import {nanoid} from 'nanoid';
import {sign, verify} from 'jsonwebtoken';
import {ADDRESS_CONTRACT, JWT_SECRET, NET_EVER} from '@app/config'
import { UserResponseInterface } from './types/userResponse.interface';
import { LoginUserDto } from './dto/login.dto';
let crypto = require('crypto');
import * as ed from 'noble-ed25519';
import { Account } from '@tonclient/appkit';



@Injectable()
export class AuthService {


    async createVerify(createUserDto: any) {

        
        const newVerify = this.generateToken();
        console.log(newVerify);


        return await newVerify;
    }

    async login(loginUserDto: LoginUserDto): Promise<any>{


        console.log(loginUserDto)

        const verify = await this.verifyMessage(loginUserDto)
        console.log(verify)
        if(!verify){
            throw new HttpException(
            'Credentials are not valid',
            HttpStatus.UNPROCESSABLE_ENTITY
            )
        }

        const pubDocDid = this.getDidDocPubKey(loginUserDto.did)
        if(!pubDocDid){
            throw new HttpException(
                'Not valid did Document',
                HttpStatus.UNPROCESSABLE_ENTITY
                )
        }

        let newUser;
        newUser.status = 'ACTIVE'
        return newUser;


    }

    async getDidContract(did): Promise<string>{
        TonClient.useBinaryLibrary(libNode);
        const tonClient = new TonClient({network: {endpoints: [NET_EVER]}});
        const DIDStorageContractAddress = ADDRESS_CONTRACT;
        const acc = new Account({abi: DIDStorageABI}, {
            address: DIDStorageContractAddress,
            client: tonClient,
            signer: signerNone()
        });
        const strDid =  did.did || did

        try {
            const response = await acc.runLocal('resolveDidDocument', {id: `0x${strDid}`});
            console.log('LOADED DID ADDRESS', response.decoded.out_messages[0].value.addrDidDocument);
            return response.decoded.out_messages[0].value.addrDidDocument;
        } catch (err) {
            console.log('DID Address load failed', err);
            return null;
        }

    }

    async getDidDoc(address): Promise<any>{
        TonClient.useBinaryLibrary(libNode);
        const tonClient = new TonClient({network: {endpoints: [NET_EVER]}});
        const strAddress =  address.addr || address

        const DIDStorageContractAddress = strAddress;
        const acc = new Account({abi: DIDDocABI}, {
            address: DIDStorageContractAddress,
            client: tonClient,
            signer: signerNone()
        });
        try {
        const response = await acc.runLocal('getDid', {});
        console.log(JSON.parse(response.decoded.out_messages[0].value.value0.didDocument));
        return JSON.parse(response.decoded.out_messages[0].value.value0.didDocument)
    } catch (err) {
        console.log('DID Document load failed', err);
        return null;
    }
    }

    async getDidDocPubKey (DidDoc): Promise<any>{

       const adrr = await this.getDidContract(DidDoc)

       let pubDoc

       pubDoc = await this.getDidDoc(adrr)

       return pubDoc.publicKey

    }


    generateToken(): string {
        const TOKEN_SIZE = 32;
        return nanoid(TOKEN_SIZE);
    }

    generateJwt(user: any): string {
        return sign({
            id: user.id,
            did: user.did
        }, JWT_SECRET);
    }

    buildUserResponse(user: any): UserResponseInterface {
        return{
            user: {
                ...user,
                token: this.generateJwt(user)
            }
        }
    }


    async signMessage(input): Promise<any> {

        const msg = input.message
        const msgHash = crypto.createHash('sha256').update(msg).digest('hex');
        console.log(msgHash)

        return await ed.sign(msgHash, input.privateKey);
    }

    async verifyMessage(input): Promise<boolean> {
        // return true;//todo delete me

        const hash = crypto.createHash('sha256').update(input.message).digest('hex');
        return await ed.verify(input.signatureHex, hash, input.did);
    }

    async jwtRead(input): Promise<string> {
        // return true;//todo delete me
        const verifyJWT = verify(input.jwt, JWT_SECRET)
        if(!verifyJWT){
            throw new HttpException(
            'Credentials are not valid',
            HttpStatus.UNPROCESSABLE_ENTITY
            )
        }
        return verifyJWT

    }

}
function UserEntity(UserEntity: any) {
    throw new Error('Function not implemented.');
}

