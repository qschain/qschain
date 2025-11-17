package org.tron.core.actuator;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import lombok.extern.slf4j.Slf4j;
import org.tron.common.utils.DecodeUtil;
import org.tron.core.capsule.TransactionResultCapsule;
import org.tron.core.capsule.WitnessCapsule;
import org.tron.core.exception.ContractExeException;
import org.tron.core.exception.ContractValidateException;
import org.tron.core.store.AccountStore;
import org.tron.core.store.WitnessStore;
import org.tron.protos.Protocol;
import org.tron.protos.contract.WitnessContract;

import java.util.Objects;

@Slf4j(topic = "actuator")
public class WitnessCreditUpdateActuator extends AbstractActuator {//consensus
    public WitnessCreditUpdateActuator() {
        super(Protocol.Transaction.Contract.ContractType.WitnessCreditUpdateContract, WitnessContract.WitnessCreditUpdateContract.class);
    }
    private void updateWitnessCredit(final WitnessContract.WitnessCreditUpdateContract contract) {
        WitnessStore witnessStore = chainBaseManager.getWitnessStore();
        WitnessCapsule witnessCapsule = witnessStore
                .get(contract.getUpdateWitness().toByteArray());
        System.out.println(witnessCapsule.getCreditScore());
        System.out.println(witnessCapsule.getAddress());
        witnessCapsule.setCreditScore(contract.getUpdateCredit());//consensus
        witnessStore.put(witnessCapsule.createDbKey(), witnessCapsule);
    }

    @Override
    public boolean execute(Object result) throws ContractExeException {
        TransactionResultCapsule ret = (TransactionResultCapsule) result;
        if (Objects.isNull(ret)) {
            throw new RuntimeException(ActuatorConstant.TX_RESULT_NULL);
        }

        long fee = calcFee();
        try {
            final WitnessContract.WitnessCreditUpdateContract witnessCreditUpdateContract = this.any
                    .unpack(WitnessContract.WitnessCreditUpdateContract.class);
            this.updateWitnessCredit(witnessCreditUpdateContract);
            ret.setStatus(fee, Protocol.Transaction.Result.code.SUCESS);
        } catch (final InvalidProtocolBufferException e) {
            logger.debug(e.getMessage(), e);
            ret.setStatus(fee, Protocol.Transaction.Result.code.FAILED);
            throw new ContractExeException(e.getMessage());
        }
        return true;
    }

    @Override
    public boolean validate() throws ContractValidateException {
        //todo mulsignature verify
        if (this.any == null) {
            throw new ContractValidateException(ActuatorConstant.CONTRACT_NOT_EXIST);
        }
        if (chainBaseManager == null) {
            throw new ContractValidateException("No account store or witness store!");
        }
        AccountStore accountStore = chainBaseManager.getAccountStore();
        WitnessStore witnessStore = chainBaseManager.getWitnessStore();
        if (!this.any.is(WitnessContract.WitnessCreditUpdateContract.class)) {
            throw new ContractValidateException(
                    "contract type error, expected type [WitnessUpdateContract],real type[" + any
                            .getClass() + "]");
        }
        final WitnessContract.WitnessCreditUpdateContract contract;
        try {
            contract = this.any.unpack(WitnessContract.WitnessCreditUpdateContract.class);
        } catch (InvalidProtocolBufferException e) {
            logger.debug(e.getMessage(), e);
            throw new ContractValidateException(e.getMessage());
        }

        byte[] ownerAddress = contract.getOwnerAddress().toByteArray();
        if (!DecodeUtil.addressValid(ownerAddress)) {
            throw new ContractValidateException("Invalid address");
        }

        if (!DecodeUtil.addressValid(contract.getUpdateWitness().toByteArray())){
            throw new ContractValidateException("Invalid address");
        }

        if (!accountStore.has(ownerAddress)) {
            throw new ContractValidateException("account does not exist");
        }

        if (!accountStore.has(contract.getUpdateWitness().toByteArray())) {
            throw new ContractValidateException("account does not exist");
        }

        if (!witnessStore.has(contract.getUpdateWitness().toByteArray())) {
            throw new ContractValidateException("Witness does not exist");
        }

        if (!witnessStore.has(ownerAddress)) {
            throw new ContractValidateException("Witness does not exist");
        }

        return true;
    }

    @Override
    public ByteString getOwnerAddress() throws InvalidProtocolBufferException {
        return any.unpack(WitnessContract.WitnessUpdateContract.class).getOwnerAddress();
    }

    @Override
    public long calcFee() {
        return 0;
    }
}
