import React, { Fragment } from "react"
import { Controller, useWatch } from "react-hook-form";
import { TextInput, SubmitBar, DatePicker, SearchField, Dropdown, Loader } from "@egovernments/digit-ui-react-components";

const SearchFields = ({ register, control, reset, tenantId, t }) => {

    const { isLoading: applicationTypesLoading, data: applicationTypes } = Digit.Hooks.ws.useWSMDMSWS.applicationTypes(Digit.ULBService.getStateId());

    const applicationType = useWatch({ control, name: "applicationType" });
    let businessServices = [];

    if (applicationType && applicationType?.code === "NEW_WATER_CONNECTION")
        businessServices = ["NewWS1"]
    else if (applicationType && applicationType?.code === "NEW_SEWERAGE_CONNECTION")
        businessServices = ["NewSW1"]
    else if (applicationType && applicationType?.code === "MODIFY_WATER_CONNECTION")
        businessServices = ["ModifyWSConnection"]
    else if (applicationType && applicationType?.code === "MODIFY_SEWERAGE_CONNECTION")
        businessServices = ["ModifySWConnection"]
    else
        businessServices = ["NewWS1", "NewSW1", "ModifyWSConnection", "ModifySWConnection"]

    const { data: statusData, isLoading } = Digit.Hooks.useApplicationStatusGeneral({ businessServices, tenantId }, {});
    let applicationStatuses = []

    statusData && statusData?.otherRoleStates?.map((status) => {
        let found = applicationStatuses.length > 0 ? applicationStatuses?.some(el => el?.code === status.applicationStatus) : false;
        if (!found) applicationStatuses.push({ code: status?.applicationStatus, i18nKey: `WF_NEWWS1_${(status?.applicationStatus)}` })
    })

    statusData && statusData?.userRoleStates?.map((status) => {
        let found = applicationStatuses.length > 0 ? applicationStatuses?.some(el => el?.code === status.applicationStatus) : false;
        if (!found) applicationStatuses.push({ code: status?.applicationStatus, i18nKey: `WF_NEWWS1_${(status?.applicationStatus)}` })
    })
    const propsForMobileNumber = {
        maxlength: 10,
        pattern: "[6-9][0-9]{9}",
        title: t("ES_SEARCH_APPLICATION_MOBILE_INVALID"),
        componentInFront: "+91"
    }
    return <>
        <SearchField>
            <label>{t("WS_ACK_COMMON_APP_NO_LABEL")}</label>
            <TextInput name="applicationNumber" inputRef={register({})} />
        </SearchField>
        <SearchField>
            <label>{t("WS_MYCONNECTIONS_CONSUMER_NO")}</label>
            <TextInput name="connectionNumber" inputRef={register({})} />
        </SearchField>
        <SearchField>
            <label>{t("CONSUMER_MOBILE_NUMBER")}</label>
            <TextInput name="mobileNumber" inputRef={register({})} {...propsForMobileNumber}/>
        </SearchField>
        {applicationTypesLoading ? <Loader /> : <SearchField>
            <label>{t("WS_APPLICATION_TYPE_LABEL")}</label>
            <Controller
                control={control}
                name="applicationType"
                render={(props) => (
                    <Dropdown
                        selected={props.value}
                        select={props.onChange}
                        onBlur={props.onBlur}
                        option={applicationTypes}
                        optionKey="i18nKey"
                        t={t}
                    />
                )}
            />
        </SearchField>}
        {isLoading ? <Loader /> : <SearchField>
            <label>{t("WS_COMMON_TABLE_COL_APPLICATION_STATUS_LABEL")}</label>
            <Controller
                control={control}
                name="applicationStatus"
                render={(props) => (
                    <Dropdown
                        selected={props.value}
                        select={props.onChange}
                        onBlur={props.onBlur}
                        option={applicationStatuses}
                        optionKey="i18nKey"
                        t={t}
                    />
                )}
            />
        </SearchField>}
        <SearchField>
            <label>{t("WS_COMMON_FROM_DATE_LABEL")}</label>
            <Controller
                render={(props) => <DatePicker date={props.value} onChange={props.onChange} />}
                name="fromDate"
                control={control}
            />
        </SearchField>
        <SearchField>
            <label>{t("WS_COMMON_TO_DATE_LABEL")}</label>
            <Controller
                render={(props) => <DatePicker date={props.value} onChange={props.onChange} />}
                name="toDate"
                control={control}
            />
        </SearchField>
        <SearchField className="submit">
            <SubmitBar label={t("ES_COMMON_SEARCH")} submit />
            <p onClick={() => {
                reset({
                    applicationType: "",
                    fromDate: "",
                    toDate: "",
                    licenseNumbers: "",
                    status: "",
                    tradeName: "",
                    offset: 0,
                    limit: 10,
                    sortBy: "commencementDate",
                    sortOrder: "DESC"
                });
            }}>{t(`CS_COMMON_CLEAR_SEARCH`)}</p>
        </SearchField>
    </>
}
export default SearchFields