package no.nordicsemi.android.mesh.transport;

import static no.nordicsemi.android.mesh.models.SigModelParser.CONFIGURATION_SERVER;
import static no.nordicsemi.android.mesh.models.SigModelParser.SCENE_SERVER;
import static no.nordicsemi.android.mesh.utils.MeshAddress.ALL_PROXIES_ADDRESS;
import static no.nordicsemi.android.mesh.utils.MeshAddress.isValidUnassignedAddress;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import no.nordicsemi.android.mesh.Features;
import no.nordicsemi.android.mesh.Group;
import no.nordicsemi.android.mesh.InternalTransportCallbacks;
import no.nordicsemi.android.mesh.MeshManagerApi;
import no.nordicsemi.android.mesh.MeshNetwork;
import no.nordicsemi.android.mesh.MeshStatusCallbacks;
import no.nordicsemi.android.mesh.NetworkKey;
import no.nordicsemi.android.mesh.control.BlockAcknowledgementMessage;
import no.nordicsemi.android.mesh.control.TransportControlMessage;
import no.nordicsemi.android.mesh.logger.MeshLogger;
import no.nordicsemi.android.mesh.models.ConfigurationServerModel;
import no.nordicsemi.android.mesh.models.SceneServer;
import no.nordicsemi.android.mesh.models.VendorModel;
import no.nordicsemi.android.mesh.opcodes.ApplicationMessageOpCodes;
import no.nordicsemi.android.mesh.opcodes.ConfigMessageOpCodes;
import no.nordicsemi.android.mesh.opcodes.ProxyConfigMessageOpCodes;
import no.nordicsemi.android.mesh.utils.AddressArray;
import no.nordicsemi.android.mesh.utils.ExtendedInvalidCipherTextException;
import no.nordicsemi.android.mesh.utils.MeshParserUtils;
import no.nordicsemi.android.mesh.utils.NetworkTransmitSettings;
import no.nordicsemi.android.mesh.utils.ProxyFilter;
import no.nordicsemi.android.mesh.utils.ProxyFilterType;
import no.nordicsemi.android.mesh.utils.RelaySettings;



class DefaultNoOperationMessageState extends MeshMessageState {

    private static final String TAG = DefaultNoOperationMessageState.class.getSimpleName();

    /**
     * Constructs the DefaultNoOperationMessageState
     *
     * @param meshMessage        {@link MeshMessage} Mesh message to be sent
     * @param meshTransport      {@link MeshTransport} Mesh transport
     * @param handlerCallbacks   {@link InternalMeshMsgHandlerCallbacks} callbacks
     * @param transportCallbacks {@link InternalTransportCallbacks} callbacks
     * @param statusCallbacks    {@link MeshStatusCallbacks} callbacks
     */
    DefaultNoOperationMessageState(@Nullable final MeshMessage meshMessage,
                                   @NonNull final MeshTransport meshTransport,
                                   @NonNull final InternalMeshMsgHandlerCallbacks handlerCallbacks,
                                   @NonNull final InternalTransportCallbacks transportCallbacks,
                                   @NonNull final MeshStatusCallbacks statusCallbacks) {
        super(meshMessage, meshTransport, handlerCallbacks, transportCallbacks, statusCallbacks);
    }

    @Override
    public MessageState getState() {
        return null;
    }

    void parseMeshPdu(@NonNull final NetworkKey key,
                      @NonNull final ProvisionedMeshNode node,
                      @NonNull final byte[] pdu,
                      @NonNull final byte[] networkHeader,
                      @NonNull final byte[] decryptedNetworkPayload,
                      final int ivIndex,
                      @NonNull final byte[] sequenceNumber) {
        final Message message;
        try {
            message = mMeshTransport.parseMeshMessage(key, node, pdu, networkHeader, decryptedNetworkPayload, ivIndex, sequenceNumber);
            if (message != null) {
                if (message instanceof AccessMessage) {
                    parseAccessMessage((AccessMessage) message);
                } else {
                    parseControlMessage((ControlMessage) message);
                }
            } else {
                MeshLogger.verbose(TAG, "Message reassembly may not be completed yet!");
            }
        } catch (ExtendedInvalidCipherTextException e) {
            MeshLogger.error(TAG, "Decryption failed in " + e.getTag() + " : " + e.getMessage());
            mMeshStatusCallbacks.onMessageDecryptionFailed(e.getTag(), e.getMessage());
        }
    }

    

    /**
     * Parses Access message received
     *
     * @param message access message received by the access layer
     */
    private void parseAccessMessage(final AccessMessage message) {
        final ProvisionedMeshNode node = mInternalTransportCallbacks.getNode(message.getSrc());
        final int opCodeLength = MeshParserUtils.getOpCodeLength(message.getAccessPdu()[0] & 0xFF);
        //OpCode length
        switch (opCodeLength) {
            case 1:
                if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_COMPOSITION_DATA_STATUS) {
                    final ConfigCompositionDataStatus status = new ConfigCompositionDataStatus(message);
                    if (!isReceivedViaProxyFilter(message)) {
                        node.setCompositionData(status);
                    }
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.HEALTH_CURRENT_STATUS) {
                    final HealthCurrentStatus healthCurrentStatus = new HealthCurrentStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(healthCurrentStatus);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), healthCurrentStatus);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.HEALTH_FAULT_STATUS) {
                    final HealthFaultStatus healthFaultStatus = new HealthFaultStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(healthFaultStatus);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), healthFaultStatus);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.SCENE_STATUS) {
                    final SceneStatus sceneStatus = new SceneStatus(message);
                    if (sceneStatus.isSuccessful()) {
                        final MeshModel model = getMeshModel(node, sceneStatus.getSrc(), SCENE_SERVER);
                        if (model != null) {
                            final SceneServer sceneServer = ((SceneServer) model);
                            sceneServer.currentScene = sceneStatus.getCurrentScene();
                            sceneServer.targetScene = sceneStatus.getTargetScene();
                        }
                    }
                    mInternalTransportCallbacks.updateMeshNetwork(sceneStatus);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), sceneStatus);
                } else if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_HEARTBEAT_PUBLICATION_STATUS) {
                    final ConfigHeartbeatPublicationStatus status = new ConfigHeartbeatPublicationStatus(message);
                    if (!isReceivedViaProxyFilter(message)) {
                        if (status.isSuccessful()) {
                            final ConfigurationServerModel model = (ConfigurationServerModel) getMeshModel(node, status.getSrc(), CONFIGURATION_SERVER);
                            if (model != null) {
                                model.setHeartbeatPublication(!isValidUnassignedAddress(status.getHeartbeatPublication().getDst()) ?
                                        status.getHeartbeatPublication() : null);
                            }
                        }
                    }
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.GENERIC_LOCATION_GLOBAL_STATUS) {
                    final GenericLocationGlobalStatus genericLocationGlobalStatus = new GenericLocationGlobalStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(genericLocationGlobalStatus);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), genericLocationGlobalStatus);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.SENSOR_DESCRIPTOR_STATUS) {
                    final SensorDescriptorStatus status = new SensorDescriptorStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.SENSOR_CADENCE_STATUS) {
                    final SensorCadenceStatus status = new SensorCadenceStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.SENSOR_SETTINGS_STATUS) {
                    final SensorSettingsStatus status = new SensorSettingsStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.SENSOR_SETTING_STATUS) {
                    final SensorSettingStatus status = new SensorSettingStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.SENSOR_STATUS) {
                    final SensorStatus status = new SensorStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.SENSOR_COLUMN_STATUS) {
                    final SensorColumnStatus status = new SensorColumnStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.SENSOR_SERIES_STATUS) {
                    final SensorSeriesStatus status = new SensorSeriesStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.SCHEDULER_ACTION_STATUS) {
                    final SchedulerActionStatus schedulerActionStatus = new SchedulerActionStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(schedulerActionStatus);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), schedulerActionStatus);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.GENERIC_ADMIN_PROPERTY_STATUS ||
                        message.getOpCode() == ApplicationMessageOpCodes.GENERIC_MANUFACTURER_PROPERTY_STATUS ||
                        message.getOpCode() == ApplicationMessageOpCodes.GENERIC_USER_PROPERTY_STATUS) {
                    final GenericPropertyStatus status = new GenericPropertyStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.TIME_STATUS) {
                    final TimeStatus timeStatus = new TimeStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(timeStatus);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), timeStatus);
                } else {
                    handleUnknownPdu(message);
                }
                break;
            case 2:
                if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_DEFAULT_TTL_STATUS) {
                    final ConfigDefaultTtlStatus status = new ConfigDefaultTtlStatus(message);
                    if (!isReceivedViaProxyFilter(message)) {
                        node.setTtl(status.getTtl());
                    }
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.GENERIC_ON_POWER_UP_STATUS) {
                    final GenericOnPowerUpStatus genericOnPowerUpStatus = new GenericOnPowerUpStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(genericOnPowerUpStatus);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), genericOnPowerUpStatus);
                } else if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_NETKEY_STATUS) {
                    final ConfigNetKeyStatus status = new ConfigNetKeyStatus(message);
                    if (!isReceivedViaProxyFilter(message)) {
                        if (status.isSuccessful()) {
                            if (mMeshMessage instanceof ConfigNetKeyAdd) {
                                node.setAddedNetKeyIndex(status.getNetKeyIndex());
                                // Let's mark any keys added to the node as insecure if the node was provisioned insecurely.
                                if (!node.isSecurelyProvisioned()) {
                                    final NetworkKey key = mInternalTransportCallbacks.getMeshNetwork().getNetKey(status.getNetKeyIndex());
                                    key.markAsInsecure();
                                }
                            } else if (mMeshMessage instanceof ConfigNetKeyUpdate) {
                                node.updateAddedNetKey(status.getNetKeyIndex());
                            } else if (mMeshMessage instanceof ConfigNetKeyDelete) {
                                node.removeAddedNetKeyIndex(status.getNetKeyIndex());
                            }
                        }
                    }
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_NETKEY_LIST) {
                    final ConfigNetKeyList netKeyList = new ConfigNetKeyList(message);
                    if (!isReceivedViaProxyFilter(message)) {
                        if (netKeyList.isSuccessful()) {
                            node.updateNetKeyList(netKeyList.getKeyIndexes());
                        }
                    }
                    mInternalTransportCallbacks.updateMeshNetwork(netKeyList);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), netKeyList);
                } else if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_APPKEY_STATUS) {
                    final ConfigAppKeyStatus status = new ConfigAppKeyStatus(message);
                    if (!isReceivedViaProxyFilter(message)) {
                        if (status.isSuccessful()) {
                            if (mMeshMessage instanceof ConfigAppKeyAdd) {
                                node.setAddedAppKeyIndex(status.getAppKeyIndex());
                            } else if (mMeshMessage instanceof ConfigAppKeyUpdate) {
                                node.updateAddedAppKey(status.getAppKeyIndex());
                            } else if (mMeshMessage instanceof ConfigAppKeyDelete) {
                                node.removeAddedAppKeyIndex(status.getAppKeyIndex());
                            }
                        }
                    }
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_APPKEY_LIST) {
                    final ConfigAppKeyList appKeyList = new ConfigAppKeyList(message);
                    if (!isReceivedViaProxyFilter(message)) {
                        if (appKeyList.isSuccessful()) {
                            node.updateAppKeyList(appKeyList.getNetKeyIndex(), appKeyList.getKeyIndexes(),
                                    mInternalTransportCallbacks.getApplicationKeys(appKeyList.getNetKeyIndex()));
                        }
                    }
                    mInternalTransportCallbacks.updateMeshNetwork(appKeyList);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), appKeyList);
                } else if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_MODEL_APP_STATUS) {
                    final ConfigModelAppStatus status = new ConfigModelAppStatus(message);
                    if (!isReceivedViaProxyFilter(message)) {
                        if (status.isSuccessful()) {
                            if (mMeshMessage instanceof ConfigModelAppBind) {
                                node.setAppKeyBindStatus(status);
                            } else {
                                node.setAppKeyUnbindStatus(status);
                            }
                        }
                    }
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_SIG_MODEL_APP_LIST) {
                    final ConfigSigModelAppList appKeyList = new ConfigSigModelAppList(message);
                    if (!isReceivedViaProxyFilter(message)) {
                        if (appKeyList.isSuccessful()) {
                            final MeshModel model = getMeshModel(node, appKeyList.getElementAddress(), appKeyList.getModelIdentifier());
                            if (model != null) {
                                model.setBoundAppKeyIndexes(appKeyList.getKeyIndexes());
                            }
                        }
                    }
                    mInternalTransportCallbacks.updateMeshNetwork(appKeyList);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), appKeyList);
                } else if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_VENDOR_MODEL_APP_LIST) {
                    final ConfigVendorModelAppList appKeyList = new ConfigVendorModelAppList(message);
                    if (!isReceivedViaProxyFilter(message)) {
                        if (appKeyList.isSuccessful()) {
                            final MeshModel model = getMeshModel(node, appKeyList.getElementAddress(), appKeyList.getModelIdentifier());
                            if (model != null) {
                                model.setBoundAppKeyIndexes(appKeyList.getKeyIndexes());
                            }
                        }
                    }
                    mInternalTransportCallbacks.updateMeshNetwork(appKeyList);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), appKeyList);
                } else if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_MODEL_PUBLICATION_STATUS) {
                    final ConfigModelPublicationStatus status = new ConfigModelPublicationStatus(message);
                    if (!isReceivedViaProxyFilter(message)) {
                        if (status.isSuccessful()) {
                            final MeshModel model = getMeshModel(node, status.getElementAddress(), status.getModelIdentifier());
                            if (model != null) {
                                if (mMeshMessage instanceof ConfigModelPublicationGet) {
                                    model.updatePublicationStatus(status);
                                } else if (mMeshMessage instanceof ConfigModelPublicationSet) {
                                    model.setPublicationStatus(status, null);
                                } else if (mMeshMessage instanceof ConfigModelPublicationVirtualAddressSet) {
                                    final UUID labelUUID = ((ConfigModelPublicationVirtualAddressSet) mMeshMessage).
                                            getLabelUuid();
                                    model.setPublicationStatus(status, labelUUID);
                                }
                            }
                        }
                    }
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_MODEL_SUBSCRIPTION_STATUS) {
                    final ConfigModelSubscriptionStatus status = new ConfigModelSubscriptionStatus(message);
                    if (!isReceivedViaProxyFilter(message)) {
                        if (status.isSuccessful()) {
                            final MeshModel model = getMeshModel(node, status.getElementAddress(), status.getModelIdentifier());
                            if (model != null) {
                                if (mMeshMessage instanceof ConfigModelSubscriptionAdd) {
                                    model.addSubscriptionAddress(status.getSubscriptionAddress());
                                } else if (mMeshMessage instanceof ConfigModelSubscriptionVirtualAddressAdd) {
                                    model.addSubscriptionAddress(((ConfigModelSubscriptionVirtualAddressAdd) mMeshMessage).
                                            getLabelUuid(), status.getSubscriptionAddress());
                                } else if (mMeshMessage instanceof ConfigModelSubscriptionOverwrite) {
                                    model.overwriteSubscriptionAddress(status.getSubscriptionAddress());
                                } else if (mMeshMessage instanceof ConfigModelSubscriptionVirtualAddressOverwrite) {
                                    model.overwriteSubscriptionAddress(((ConfigModelSubscriptionVirtualAddressOverwrite) mMeshMessage).
                                            getLabelUuid(), status.getSubscriptionAddress());
                                } else if (mMeshMessage instanceof ConfigModelSubscriptionDelete) {
                                    model.removeSubscriptionAddress(status.getSubscriptionAddress());
                                } else if (mMeshMessage instanceof ConfigModelSubscriptionVirtualAddressDelete) {
                                    model.removeSubscriptionAddress(((ConfigModelSubscriptionVirtualAddressDelete) mMeshMessage).
                                            getLabelUuid(), status.getSubscriptionAddress());
                                } else if (mMeshMessage instanceof ConfigModelSubscriptionDeleteAll) {
                                    model.removeAllSubscriptionAddresses();
                                }
                            }
                        }
                    }
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_SIG_MODEL_SUBSCRIPTION_LIST) {
                    final ConfigSigModelSubscriptionList status = new ConfigSigModelSubscriptionList(message);
                    if (!isReceivedViaProxyFilter(message)) {
                        if (status.isSuccessful()) {
                            final MeshModel model = getMeshModel(node, status.getElementAddress(), status.getModelIdentifier());
                            if (model != null) {
                                model.updateSubscriptionAddressesList(status.getSubscriptionAddresses());
                            }
                            createGroups(status.getSubscriptionAddresses());
                        }
                    }
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_VENDOR_MODEL_SUBSCRIPTION_LIST) {
                    final ConfigVendorModelSubscriptionList status = new ConfigVendorModelSubscriptionList(message);
                    if (!isReceivedViaProxyFilter(message)) {
                        if (status.isSuccessful()) {
                            final MeshModel model = getMeshModel(node, status.getElementAddress(), status.getModelIdentifier());
                            if (model != null) {
                                model.updateSubscriptionAddressesList(status.getSubscriptionAddresses());
                            }
                            createGroups(status.getSubscriptionAddresses());
                        }
                    }
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_HEARTBEAT_SUBSCRIPTION_STATUS) {
                    final ConfigHeartbeatSubscriptionStatus status = new ConfigHeartbeatSubscriptionStatus(message);
                    if (!isReceivedViaProxyFilter(message)) {
                        if (status.isSuccessful()) {
                            final MeshModel model = getMeshModel(node, message.getSrc(), CONFIGURATION_SERVER);
                            if (model != null) {
                                ((ConfigurationServerModel) model).
                                        setHeartbeatSubscription((!isValidUnassignedAddress(status.getHeartbeatSubscription().getSrc()) ||
                                                !isValidUnassignedAddress(status.getHeartbeatSubscription().getDst()))
                                                ? status.getHeartbeatSubscription() : null);
                            }
                        }
                    }
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_NODE_IDENTITY_STATUS) {
                    final ConfigNodeIdentityStatus status = new ConfigNodeIdentityStatus(message);
                    if (!isReceivedViaProxyFilter(message)) {
                        node.nodeIdentityState = status.getNodeIdentityState();
                    }
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_NODE_RESET_STATUS) {
                    final ConfigNodeResetStatus status = new ConfigNodeResetStatus(message);
                    if (!isReceivedViaProxyFilter(message)) {
                        mInternalTransportCallbacks.onMeshNodeReset(node);
                    }
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_NETWORK_TRANSMIT_STATUS) {
                    final ConfigNetworkTransmitStatus status = new ConfigNetworkTransmitStatus(message);
                    final NetworkTransmitSettings networkTransmitSettings =
                            new NetworkTransmitSettings(status.getNetworkTransmitCount(), status.getNetworkTransmitIntervalSteps());
                    node.setNetworkTransmitSettings(networkTransmitSettings);
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_RELAY_STATUS) {
                    final ConfigRelayStatus status = new ConfigRelayStatus(message);
                    if (!isReceivedViaProxyFilter(message)) {
                        final RelaySettings relaySettings =
                                new RelaySettings(status.getRelayRetransmitCount(), status.getRelayRetransmitIntervalSteps());
                        node.setRelaySettings(relaySettings);
                        // Let's update the feature state based on the status message.
                        node.nodeFeatures.setRelay(status.isEnabled() ? Features.ENABLED : Features.DISABLED);
                    }
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_BEACON_STATUS) {
                    final ConfigBeaconStatus status = new ConfigBeaconStatus(message);
                    if (!isReceivedViaProxyFilter(message)) {
                        node.setSecureNetworkBeaconSupported(status.isEnable());
                    }
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_FRIEND_STATUS) {
                    final ConfigFriendStatus status = new ConfigFriendStatus(message);
                    if (!isReceivedViaProxyFilter(message)) {
                        node.nodeFeatures.setFriend(status.isEnabled() ? Features.ENABLED : Features.DISABLED);
                    }
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_KEY_REFRESH_PHASE_STATUS) {
                    final ConfigKeyRefreshPhaseStatus status = new ConfigKeyRefreshPhaseStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_GATT_PROXY_STATUS) {
                    final ConfigGattProxyStatus status = new ConfigGattProxyStatus(message);
                    if (!isReceivedViaProxyFilter(message)) {
                        node.nodeFeatures.setProxy(status.isProxyFeatureEnabled() ? Features.ENABLED : Features.DISABLED);
                    }
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ConfigMessageOpCodes.CONFIG_LOW_POWER_NODE_POLLTIMEOUT_STATUS) {
                    final ConfigLowPowerNodePollTimeoutStatus status = new ConfigLowPowerNodePollTimeoutStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.GENERIC_ON_OFF_STATUS) {
                    final GenericOnOffStatus status = new GenericOnOffStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.GENERIC_LEVEL_STATUS) {
                    final GenericLevelStatus genericLevelStatus = new GenericLevelStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(genericLevelStatus);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), genericLevelStatus);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.GENERIC_POWER_LEVEL_STATUS) {
                    final GenericPowerLevelStatus genericPowerLevelStatus = new GenericPowerLevelStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(genericPowerLevelStatus);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), genericPowerLevelStatus);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.GENERIC_BATTERY_STATUS) {
                    final GenericBatteryStatus status = new GenericBatteryStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.LIGHT_LIGHTNESS_STATUS) {
                    final LightLightnessStatus lightLightnessStatus = new LightLightnessStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(lightLightnessStatus);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), lightLightnessStatus);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.LIGHT_CTL_STATUS) {
                    final LightCtlStatus lightCtlStatus = new LightCtlStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(lightCtlStatus);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), lightCtlStatus);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.LIGHT_CTL_TEMPERATURE_RANGE_STATUS) {
                    final LightCtlTemperatureRangeStatus lightCtlTemperatureRangeStatus = new LightCtlTemperatureRangeStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(lightCtlTemperatureRangeStatus);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), lightCtlTemperatureRangeStatus);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.LIGHT_HSL_STATUS) {
                    final LightHslStatus lightHslStatus = new LightHslStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(lightHslStatus);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), lightHslStatus);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.LIGHT_LC_MODE_STATUS) {
                    final LightLCModeStatus lightLcModeStatus = new LightLCModeStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(lightLcModeStatus);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), lightLcModeStatus);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.LIGHT_LC_OCCUPANCY_MODE_STATUS) {
                    final LightLCOccupancyModeStatus lightLcOccupancyModeStatus = new LightLCOccupancyModeStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(lightLcOccupancyModeStatus);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), lightLcOccupancyModeStatus);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.LIGHT_LC_LIGHT_ON_OFF_STATUS) {
                    final LightLCLightOnOffStatus lightLcLightOnOffStatus = new LightLCLightOnOffStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(lightLcLightOnOffStatus);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), lightLcLightOnOffStatus);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.LIGHT_LC_PROPERTY_STATUS) {
                    final LightLCPropertyStatus status = new LightLCPropertyStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.SCENE_REGISTER_STATUS) {
                    if (mMeshMessage instanceof SceneRegisterGet) {
                        final SceneRegisterStatus status = new SceneRegisterStatus(message);
                        mInternalTransportCallbacks.updateMeshNetwork(status);
                        mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                    } else if (mMeshMessage instanceof SceneStore) {
                        final SceneRegisterStatus status = new SceneRegisterStatus(message);
                        storeScene(node, status);
                        mInternalTransportCallbacks.updateMeshNetwork(status);
                        mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                    } else if (mMeshMessage instanceof SceneRecall) {
                        final SceneStatus status = new SceneStatus(message);
                        storeScene(node, status);
                        mInternalTransportCallbacks.updateMeshNetwork(status);
                        mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                    } else if (mMeshMessage instanceof SceneDelete) {
                        final SceneRegisterStatus status = new SceneRegisterStatus(message);
                        deleteScene(node, status);
                        mInternalTransportCallbacks.updateMeshNetwork(status);
                        mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                    }
                } else if (message.getOpCode() == ApplicationMessageOpCodes.SCHEDULER_STATUS) {
                    final SchedulerStatus schedulerStatus = new SchedulerStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(schedulerStatus);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), schedulerStatus);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.TIME_ZONE_STATUS) {
                    final TimeZoneStatus timeZoneStatus = new TimeZoneStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(timeZoneStatus);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), timeZoneStatus);
                } else if (message.getOpCode() == ApplicationMessageOpCodes.GENERIC_DEFAULT_TRANSITION_TIME_STATUS) {
                    final GenericDefaultTransitionTimeStatus genericDefaultTransitionTimeStatus = new GenericDefaultTransitionTimeStatus(message);
                    mInternalTransportCallbacks.updateMeshNetwork(genericDefaultTransitionTimeStatus);
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), genericDefaultTransitionTimeStatus);
                } else {
                    handleUnknownPdu(message);
                }
                break;
            case 3:
                if (mMeshMessage instanceof VendorModelMessageAcked) {
                    final VendorModelMessageAcked vendorModelMessageAcked = (VendorModelMessageAcked) mMeshMessage;
                    final VendorModelMessageStatus status = new VendorModelMessageStatus(message, vendorModelMessageAcked.getModelIdentifier());
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                    MeshLogger.verbose(TAG, "Vendor model Access PDU Received: " + MeshParserUtils.bytesToHex(message.getAccessPdu(), false));
                } else if (mMeshMessage instanceof VendorModelMessageUnacked) {
                    final VendorModelMessageUnacked vendorModelMessageUnacked = (VendorModelMessageUnacked) mMeshMessage;
                    final VendorModelMessageStatus status = new VendorModelMessageStatus(message, vendorModelMessageUnacked.getModelIdentifier());
                    mMeshStatusCallbacks.onMeshMessageReceived(message.getSrc(), status);
                } else {
                       // Try resolving unsolicited vendor messages.
    if (!tryResolveVendorModelAndDispatch(message, node)) {

        // Preserve original SDK behavior.
        handleUnknownPdu(message);
    }else{
        MeshLogger.verbose(TAG, "else tryResolveVendorModelAndDispatch is true");
    }

                }
                break;
        }
    }
/**
 * Resolves unsolicited vendor messages using the
 * source element's composition data.
 *
 * Returns true only when exactly one matching
 * vendor model is found.
 */
private boolean tryResolveVendorModelAndDispatch(
        @NonNull final AccessMessage message,
        @Nullable final ProvisionedMeshNode node) {

    MeshLogger.verbose(TAG,
            "🔍 VENDOR_FALLBACK [START] src=0x" +
                    Integer.toHexString(message.getSrc()) +
                    " dst=0x" +
                    Integer.toHexString(message.getDst()));

    final byte[] accessPdu = message.getAccessPdu();

    // STEP 1: Validate Access PDU
    if (accessPdu == null) {
        MeshLogger.error(TAG,
                "❌ VENDOR_FALLBACK [STEP 1] FAILED: Access PDU is NULL");
        return false;
    }

    MeshLogger.verbose(TAG,
            "🔍 VENDOR_FALLBACK [STEP 1] Access PDU=" +
                    MeshParserUtils.bytesToHex(accessPdu, false) +
                    " length=" + accessPdu.length);

    if (accessPdu.length < 3) {
        MeshLogger.error(TAG,
                "❌ VENDOR_FALLBACK [STEP 1] FAILED: PDU length < 3");
        return false;
    }

    if ((accessPdu[0] & 0xC0) != 0xC0) {
        MeshLogger.error(TAG,
                "❌ VENDOR_FALLBACK [STEP 1] FAILED: Not a 3-byte vendor opcode");
        return false;
    }

    MeshLogger.verbose(TAG,
            "✅ VENDOR_FALLBACK [STEP 1] Valid vendor Access PDU");

    // STEP 2: Validate node
    if (node == null) {
        MeshLogger.error(TAG,
                "❌ VENDOR_FALLBACK [STEP 2] FAILED: Source node is NULL");
        return false;
    }

    if (node.getElements() == null) {
        MeshLogger.error(TAG,
                "❌ VENDOR_FALLBACK [STEP 2] FAILED: Node elements are NULL");
        return false;
    }

    MeshLogger.verbose(TAG,
            "✅ VENDOR_FALLBACK [STEP 2] Node found. Total elements=" +
                    node.getElements().size());

    // STEP 3: Extract company ID and opcode
    final int companyId =
            (accessPdu[1] & 0xFF) |
                    ((accessPdu[2] & 0xFF) << 8);

    final int vendorOpcode = accessPdu[0] & 0xFF;

    MeshLogger.verbose(TAG,
            "🔍 VENDOR_FALLBACK [STEP 3] Company ID=0x" +
                    Integer.toHexString(companyId) +
                    " Vendor Opcode=0x" +
                    Integer.toHexString(vendorOpcode));

    // STEP 4: Find exact source element
    final Element element =
            node.getElements().get(message.getSrc());

    if (element == null) {
        MeshLogger.error(TAG,
                "❌ VENDOR_FALLBACK [STEP 4] FAILED: Element not found for src=0x" +
                        Integer.toHexString(message.getSrc()));
        return false;
    }

    if (element.getMeshModels() == null) {
        MeshLogger.error(TAG,
                "❌ VENDOR_FALLBACK [STEP 4] FAILED: Element models are NULL");
        return false;
    }

    MeshLogger.verbose(TAG,
            "✅ VENDOR_FALLBACK [STEP 4] Element found. Total models=" +
                    element.getMeshModels().size());

    // STEP 5: Resolve expected model ID
    final int expectedModelId =
            getModelIdForVendorOpcode(vendorOpcode);

    MeshLogger.verbose(TAG,
            "🔍 VENDOR_FALLBACK [STEP 5] Expected Model ID=0x" +
                    Integer.toHexString(expectedModelId));

    if (expectedModelId == -1) {
        MeshLogger.error(TAG,
                "❌ VENDOR_FALLBACK [STEP 5] FAILED: No model mapping for opcode=0x" +
                        Integer.toHexString(vendorOpcode));
        return false;
    }

    // STEP 6: Search matching vendor model
    Integer resolvedModelId = null;

    int totalModels = 0;
    int vendorModels = 0;
    int companyMatches = 0;

    for (MeshModel candidate : element.getMeshModels().values()) {

        totalModels++;

        if (!(candidate instanceof VendorModel)) {
            MeshLogger.verbose(TAG,
                    "⏭️ VENDOR_FALLBACK [STEP 6] Skipping non-vendor model=0x" +
                            Integer.toHexString(candidate.getModelId()));
            continue;
        }

        vendorModels++;

        final VendorModel vendorModel = (VendorModel) candidate;

        final int candidateCompanyId =
                vendorModel.getCompanyIdentifier() & 0xFFFF;

        final int candidateModelId =
                candidate.getModelId();

        MeshLogger.verbose(TAG,
                "🔍 VENDOR_FALLBACK [STEP 6] Checking model=0x" +
                        Integer.toHexString(candidateModelId) +
                        " company=0x" +
                        Integer.toHexString(candidateCompanyId));

        if (candidateCompanyId != companyId) {
            MeshLogger.verbose(TAG,
                    "⏭️ VENDOR_FALLBACK [STEP 6] Company ID mismatch");
            continue;
        }

        companyMatches++;

        if ((candidateModelId & 0xFFFF) != expectedModelId) {
            MeshLogger.verbose(TAG,
                    "⏭️ VENDOR_FALLBACK [STEP 6] Model ID mismatch. " +
                            "Expected=0x" +
                            Integer.toHexString(expectedModelId) +
                            " Actual=0x" +
                            Integer.toHexString(candidateModelId & 0xFFFF));
            continue;
        }

        if (resolvedModelId != null) {
            MeshLogger.error(TAG,
                    "❌ VENDOR_FALLBACK [STEP 6] FAILED: Multiple matching vendor models. " +
                            "First=0x" +
                            Integer.toHexString(resolvedModelId) +
                            " Second=0x" +
                            Integer.toHexString(candidateModelId));
            return false;
        }

        resolvedModelId = candidateModelId;

        MeshLogger.verbose(TAG,
                "✅ VENDOR_FALLBACK [STEP 6] Matching vendor model found=0x" +
                        Integer.toHexString(resolvedModelId));
    }

    MeshLogger.verbose(TAG,
            "🔍 VENDOR_FALLBACK [STEP 6] Search summary: " +
                    "totalModels=" + totalModels +
                    " vendorModels=" + vendorModels +
                    " companyMatches=" + companyMatches);

    // STEP 7: Validate resolved model
    if (resolvedModelId == null) {
        MeshLogger.error(TAG,
                "❌ VENDOR_FALLBACK [STEP 7] FAILED: No matching vendor model found. " +
                        "src=0x" +
                        Integer.toHexString(message.getSrc()) +
                        " company=0x" +
                        Integer.toHexString(companyId) +
                        " expectedModel=0x" +
                        Integer.toHexString(expectedModelId));
        return false;
    }

    MeshLogger.verbose(TAG,
            "✅ VENDOR_FALLBACK [STEP 7] Resolved Model ID=0x" +
                    Integer.toHexString(resolvedModelId));

    // STEP 8: Construct vendor status
    final VendorModelMessageStatus status =
            new VendorModelMessageStatus(
                    message,
                    resolvedModelId
            );

    MeshLogger.verbose(TAG,
            "✅ VENDOR_FALLBACK [STEP 8] VendorModelMessageStatus created");

    // STEP 9: Dispatch message
    mMeshStatusCallbacks.onMeshMessageReceived(
            message.getSrc(),
            status
    );

    MeshLogger.verbose(TAG,
            "✅ VENDOR_FALLBACK [SUCCESS] Message dispatched. " +
                    "src=0x" +
                    Integer.toHexString(message.getSrc()) +
                    " model=0x" +
                    Integer.toHexString(resolvedModelId));

    return true;
}

private int getModelIdForVendorOpcode(int opcode) {
    switch (opcode) {
        case 0xE3:
            return 0x0001; // Replace with actual Model A ID

        case 0xE4:
            return 0x0002; // Replace with actual Model B ID

        default:
            return -1;
    }
}

    
    private void handleUnknownPdu(final AccessMessage message) {
        MeshLogger.verbose(TAG, "Unknown Access PDU Received: " + MeshParserUtils.bytesToHex(message.getAccessPdu(), false));
        mMeshStatusCallbacks.onUnknownPduReceived(message.getSrc(), message.getAccessPdu());
    }

    /**
     * Parses control message received
     *
     * @param controlMessage control message received by the transport layer
     */
    private void parseControlMessage(final ControlMessage controlMessage) {
        //Get the segment count count of the access message
        final int segmentCount = message.getNetworkLayerPdu().size();
        if (controlMessage.getPduType() == MeshManagerApi.PDU_TYPE_NETWORK) {
            final TransportControlMessage transportControlMessage = controlMessage.getTransportControlMessage();
            if (transportControlMessage.getState() == TransportControlMessage.TransportControlMessageState.LOWER_TRANSPORT_BLOCK_ACKNOWLEDGEMENT) {
                MeshLogger.verbose(TAG, "Acknowledgement payload: " + MeshParserUtils.bytesToHex(controlMessage.getTransportControlPdu(), false));
                final ArrayList<Integer> retransmitPduIndexes = BlockAcknowledgementMessage.getSegmentsToBeRetransmitted(controlMessage.getTransportControlPdu(), segmentCount);
                mMeshStatusCallbacks.onBlockAcknowledgementReceived(controlMessage.getSrc(), controlMessage);
                executeResend(retransmitPduIndexes);
            } else if (transportControlMessage.getState() == TransportControlMessage.TransportControlMessageState.LOWER_TRANSPORT_HEARTBEAT_MESSAGE) {
                MeshLogger.verbose(TAG, "Heartbeat message received");
                mMeshStatusCallbacks.onHeartbeatMessageReceived(controlMessage.getSrc(), controlMessage);
            } else {
                MeshLogger.verbose(TAG, "Unexpected control message received, ignoring message");
                mMeshStatusCallbacks.onUnknownPduReceived(controlMessage.getSrc(), controlMessage.getTransportControlPdu());
            }
        } else if (controlMessage.getPduType() == MeshManagerApi.PDU_TYPE_PROXY_CONFIGURATION) {
            if (controlMessage.getOpCode() == ProxyConfigMessageOpCodes.FILTER_STATUS) {
                final ProxyConfigFilterStatus status = new ProxyConfigFilterStatus(controlMessage);
                final ProxyFilter filter;
                if (mMeshMessage instanceof ProxyConfigSetFilterType) {
                    filter = new ProxyFilter(status.getFilterType());
                    mInternalTransportCallbacks.setProxyFilter(filter);
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(controlMessage.getSrc(), status);
                } else if (mMeshMessage instanceof ProxyConfigAddAddressToFilter) {
                    filter = updateProxyFilter(mInternalTransportCallbacks.getProxyFilter(), status.getFilterType());
                    final ProxyConfigAddAddressToFilter addAddressToFilter = (ProxyConfigAddAddressToFilter) mMeshMessage;
                    for (AddressArray addressArray : addAddressToFilter.getAddresses()) {
                        filter.addAddress(addressArray);
                    }
                    mInternalTransportCallbacks.setProxyFilter(filter);
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(controlMessage.getSrc(), status);

                } else if (mMeshMessage instanceof ProxyConfigRemoveAddressFromFilter) {
                    filter = updateProxyFilter(mInternalTransportCallbacks.getProxyFilter(), status.getFilterType());
                    final ProxyConfigRemoveAddressFromFilter removeAddressFromFilter = (ProxyConfigRemoveAddressFromFilter) mMeshMessage;
                    for (AddressArray addressArray : removeAddressFromFilter.getAddresses()) {
                        filter.removeAddress(addressArray);
                    }
                    mInternalTransportCallbacks.setProxyFilter(filter);
                    mInternalTransportCallbacks.updateMeshNetwork(status);
                    mMeshStatusCallbacks.onMeshMessageReceived(controlMessage.getSrc(), status);
                }
            }
        }
    }

    /**
     * Checks and returns a new filter or the existing filter
     *
     * @param currentFilter Proxy filter that is currently set on this node
     * @param filterType    Type of {@link ProxyFilterType} that was received by the status message
     */
    private ProxyFilter updateProxyFilter(final ProxyFilter currentFilter,
                                          final ProxyFilterType filterType) {
        if (currentFilter != null && currentFilter.getFilterType().getType() == filterType.getType()) {
            return currentFilter;
        } else {
            return new ProxyFilter(filterType);
        }
    }

    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    private boolean isReceivedViaProxyFilter(@NonNull final Message message) {
        final ProxyFilter filter = mInternalTransportCallbacks.getProxyFilter();
        if (filter != null && !filter.getAddresses().isEmpty()) {
            if (filter.getFilterType().getType() == ProxyFilterType.INCLUSION_LIST_FILTER) {
                return filterAddressMatches(filter, message.getDst());
            } else {
                return !filterAddressMatches(filter, message.getDst());
            }
        }
        return false;
    }

    private boolean filterAddressMatches(@NonNull final ProxyFilter filter, final int dst) {
        for (AddressArray addressArray : filter.getAddresses()) {
            final int address = MeshParserUtils.unsignedBytesToInt(addressArray.getAddress()[1], addressArray.getAddress()[0]);
            if (address == dst) {
                return true;
            }
        }
        return false;
    }

    private void createGroups(@NonNull final List<Integer> subscriptionAddresses) {
        final MeshNetwork network = mInternalTransportCallbacks.getMeshNetwork();
        for (Integer groupAddress : subscriptionAddresses) {
            if (groupAddress < ALL_PROXIES_ADDRESS) {
                Group group = network.getGroup(groupAddress);
                if (group == null) {
                    group = new Group(groupAddress, network.getMeshUUID());
                    group.setName("Unknown Group");
                    mInternalTransportCallbacks.addGroup(group);
                }
            }
        }
    }

    private MeshModel getMeshModel(final ProvisionedMeshNode node, final int src, final int modelId) {
        final Element element = node.getElements().get(src);
        if (element != null) {
            return element.getMeshModels().get(modelId);
        }
        return null;
    }

    private void storeScene(final ProvisionedMeshNode node, final SceneRegisterStatus status) {
        if (status.isSuccessful()) {
            final SceneServer sceneServer = (SceneServer) getMeshModel(node, status.getSrc(), SCENE_SERVER);
            if (sceneServer != null) {
                mInternalTransportCallbacks.storeScene(status.getSrc(), status.getCurrentScene(), status.getSceneList());
                if (!sceneServer.sceneNumbers.contains(status.getCurrentScene())) {
                    sceneServer.sceneNumbers.add(status.getCurrentScene());
                }
                sceneServer.currentScene = status.getCurrentScene();
            }
        }
    }

    private void storeScene(final ProvisionedMeshNode node, final SceneStatus status) {
        if (status.isSuccessful()) {
            final SceneServer sceneServer = (SceneServer) getMeshModel(node, status.getSrc(), SCENE_SERVER);
            if (sceneServer != null) {
                sceneServer.currentScene = status.getCurrentScene();
            }
        }
    }

    private void deleteScene(final ProvisionedMeshNode node, final SceneRegisterStatus status) {
        if (status.isSuccessful()) {
            final SceneServer sceneServer = (SceneServer) getMeshModel(node, status.getSrc(), SCENE_SERVER);
            if (sceneServer != null) {
                final int deletedScene = ((SceneDelete) mMeshMessage).getSceneNumber();
                mInternalTransportCallbacks.deleteScene(status.getSrc(), deletedScene, status.getSceneList());
                if (sceneServer.sceneNumbers.contains(deletedScene))
                    sceneServer.sceneNumbers.remove((Integer) deletedScene);
            }
        }
    }
}