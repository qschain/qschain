package org.tron.core.actuator;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import lombok.extern.slf4j.Slf4j;
import org.tron.common.parameter.CommonParameter;
import org.tron.common.utils.DecodeUtil;
import org.tron.common.utils.StringUtil;
import org.tron.core.capsule.ProposalCapsule;
import org.tron.core.capsule.TransactionResultCapsule;
import org.tron.core.exception.ContractExeException;
import org.tron.core.exception.ContractValidateException;
import org.tron.core.utils.ProposalUtil;
import org.tron.protos.Protocol;
import org.tron.protos.contract.ProposalContract;
import java.util.Objects;

import static org.tron.core.actuator.ActuatorConstant.*;
import static org.tron.core.actuator.ActuatorConstant.NOT_EXIST_STR;

@Slf4j(topic = "actuator")
public class ProposalAntiBriberyActuator extends AbstractActuator{
    public ProposalAntiBriberyActuator() {
        super(Protocol.Transaction.Contract.ContractType.ProposalAntiBriberyActuator, ProposalContract.ProposalAntiBriberyContract.class);
    }
    @Override
    public boolean execute(Object result) throws ContractExeException{
        TransactionResultCapsule ret = (TransactionResultCapsule) result;
        if (Objects.isNull(ret)) {
            throw new RuntimeException(ActuatorConstant.TX_RESULT_NULL);
        }

        long fee = calcFee();

        try {
            final ProposalContract.ProposalAntiBriberyContract proposalAntiBriberyContract = this.any
                    .unpack(ProposalContract.ProposalAntiBriberyContract.class);
            long id = chainBaseManager.getDynamicPropertiesStore().getLatestProposalNum() + 1;
            ProposalCapsule proposalCapsule =
                    new ProposalCapsule(proposalAntiBriberyContract.getOwnerAddress(), id);
            ByteString evidence = proposalAntiBriberyContract.getEvidenceHash();
            ByteString witnessAddr = proposalAntiBriberyContract.getWitnessAddress();
            ByteString[] paramsArr = {evidence,witnessAddr};
            proposalCapsule.setParamArray(paramsArr);

            long now = chainBaseManager.getDynamicPropertiesStore().getLatestBlockHeaderTimestamp();
            long maintenanceTimeInterval = chainBaseManager.getDynamicPropertiesStore()
                    .getMaintenanceTimeInterval();
            proposalCapsule.setCreateTime(now);

            long currentMaintenanceTime =
                    chainBaseManager.getDynamicPropertiesStore().getNextMaintenanceTime();
            long now3 = now + CommonParameter.getInstance().getProposalExpireTime();
            long round = (now3 - currentMaintenanceTime) / maintenanceTimeInterval;
            long expirationTime =
                    currentMaintenanceTime + (round + 1) * maintenanceTimeInterval;
            proposalCapsule.setExpirationTime(expirationTime);

            chainBaseManager.getProposalStore().put(proposalCapsule.createDbKey(), proposalCapsule);
            chainBaseManager.getDynamicPropertiesStore().saveLatestProposalNum(id);

            ret.setStatus(fee, Protocol.Transaction.Result.code.SUCESS);
        } catch (InvalidProtocolBufferException e) {
            logger.debug(e.getMessage(), e);
            ret.setStatus(fee, Protocol.Transaction.Result.code.FAILED);
            throw new ContractExeException(e.getMessage());
        }
        return true;
    }
    @Override
    public boolean validate() throws ContractValidateException {
        if (this.any == null) {
            throw new ContractValidateException(ActuatorConstant.CONTRACT_NOT_EXIST);
        }
        if (chainBaseManager == null) {
            throw new ContractValidateException("No dbManager!");
        }
        if (!this.any.is(ProposalContract.ProposalAntiBriberyContract.class)) {
            throw new ContractValidateException(
                    "contract type error,expected type [ProposalAntiBriberyContract],real type[" + any
                            .getClass() + "]");
        }
        final ProposalContract.ProposalAntiBriberyContract contract;
        try {
            contract = this.any.unpack(ProposalContract.ProposalAntiBriberyContract.class);
        } catch (InvalidProtocolBufferException e) {
            throw new ContractValidateException(e.getMessage());
        }

        byte[] ownerAddress = contract.getOwnerAddress().toByteArray();
        String readableOwnerAddress = StringUtil.createReadableString(ownerAddress);

        if (!DecodeUtil.addressValid(ownerAddress)) {
            throw new ContractValidateException("Invalid address");
        }

        if (!chainBaseManager.getAccountStore().has(ownerAddress)) {
            throw new ContractValidateException(
                    ACCOUNT_EXCEPTION_STR + readableOwnerAddress + NOT_EXIST_STR);
        }

        if (!chainBaseManager.getWitnessStore().has(ownerAddress)) {
            throw new ContractValidateException(
                    WITNESS_EXCEPTION_STR + readableOwnerAddress + NOT_EXIST_STR);
        }

        if (contract.getWitnessAddress() == null) {
            throw new ContractValidateException("This proposal has no bribery witness address.");
        }
        if (contract.getEvidenceHash() == null){
            throw new ContractValidateException("This proposal has no evidenceHash.");
        }
        return true;
    }
    @Override
    public ByteString getOwnerAddress() throws InvalidProtocolBufferException {
        return any.unpack(ProposalContract.ProposalAntiBriberyContract.class).getOwnerAddress();
    }
    @Override
    public long calcFee() {
        return 0;
    }
}
