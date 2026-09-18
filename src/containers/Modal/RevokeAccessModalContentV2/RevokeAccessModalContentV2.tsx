// Modified for independent evaluation: no revocation claim without rekey.
import React from 'react'

import { Button, Dialog, Text, useTheme } from '@tetherto/pearpass-lib-ui-kit'

import { createStyles } from './RevokeAccessModalContentV2.styles'
import { useModal } from '../../../context/ModalContext'
import { useTranslation } from '../../../hooks/useTranslation'

export type RevokeAccessModalContentV2Props = {
  vaultId: string
  targetDeviceId: string
  deviceName: string
  onClose?: () => void
}

export const RevokeAccessModalContentV2 = ({
  deviceName,
  onClose
}: RevokeAccessModalContentV2Props) => {
  const { t } = useTranslation()
  const { theme } = useTheme()
  const styles = createStyles()
  const { closeModal } = useModal()

  const handleClose = onClose ?? closeModal

  // Keep this action disabled until authenticated key distribution and durable
  // epoch cutover are integrated. A best-effort wipe is not read revocation.
  return (
    <Dialog
      title={t('Revoke access for {deviceName}?', { deviceName })}
      onClose={handleClose}
      testID="revoke-access-dialog-v2"
      closeButtonTestID="revoke-access-close-v2"
      footer={
        <>
          <Button
            variant="secondary"
            size="small"
            type="button"
            onClick={handleClose}
            data-testid="revoke-access-cancel-v2"
          >
            {t('Cancel')}
          </Button>
          <Button
            variant="destructive"
            size="small"
            type="button"
            disabled
            data-testid="revoke-access-submit-v2"
          >
            {t('Revoke Access')}
          </Button>
        </>
      }
    >
      <div style={styles.body} data-testid="revoke-access-body-v2">
        <div style={styles.intro}>
          <Text
            as="p"
            variant="caption"
            color={theme.colors.colorTextSecondary}
          >
            {t('Secure device removal is unavailable in this evaluation build.')}
          </Text>
          <Text
            as="p"
            variant="caption"
            color={theme.colors.colorTextSecondary}
          >
            {t('Removing write access alone does not stop a device from reading future changes. This action is disabled until key rotation is integrated.')}
          </Text>
        </div>
        <ul style={styles.bulletList}>
          <li style={styles.bulletItem}>
            <Text as="span" variant="caption">
              {t(
                'For Your Security: We recommend moving your items to a new vault and updating your passwords. This is especially important if the device was lost or stolen, as it ensures your data remains protected even if a local copy exists on the revoked device.'
              )}
            </Text>
          </li>
          <li style={styles.bulletItem}>
            <Text as="span" variant="caption">
              {t(
                'Previously copied secrets cannot be recalled. Lost-device recovery also requires changing the passwords or tokens at their source.'
              )}
            </Text>
          </li>
        </ul>
      </div>
    </Dialog>
  )
}
