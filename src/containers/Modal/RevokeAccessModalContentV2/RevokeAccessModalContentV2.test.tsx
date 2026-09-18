// SPDX-License-Identifier: Apache-2.0
import React from 'react'

import { fireEvent, render, screen } from '@testing-library/react'
import '@testing-library/jest-dom'
import { ThemeProvider } from '@tetherto/pearpass-lib-ui-kit'
import { kickDevice } from '@tetherto/pearpass-lib-vault'

import { RevokeAccessModalContentV2 } from './RevokeAccessModalContentV2'

const mockClose = jest.fn()
jest.mock('../../../context/ModalContext', () => ({ useModal: () => ({ closeModal: mockClose }) }))
jest.mock('../../../hooks/useTranslation', () => ({ useTranslation: () => ({ t: (s: string) => s }) }))
jest.mock('@tetherto/pearpass-lib-vault', () => ({ kickDevice: jest.fn() }))

const show = (onClose?: () => void) => render(
  <ThemeProvider>
    <RevokeAccessModalContentV2 vaultId="dummy-vault" targetDeviceId="dummy-device"
      deviceName="Dummy device" onClose={onClose} />
  </ThemeProvider>
)

describe('evaluation device removal safety gate', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })
  test('destructive action is disabled and cannot send the upstream kick', () => {
    show()
    const submit = screen.getByTestId('revoke-access-submit-v2')
    expect(submit).toBeDisabled()
    fireEvent.click(submit)
    expect(kickDevice).not.toHaveBeenCalled()
    expect(mockClose).not.toHaveBeenCalled()
  })
  test('explains absent rekey without claiming access has been removed', () => {
    show()
    expect(screen.getByText('Secure device removal is unavailable in this evaluation build.')).toBeInTheDocument()
    expect(screen.getByText(/Removing write access alone does not stop a device/)).toBeInTheDocument()
    expect(screen.queryByText(/no longer has access to this vault/)).not.toBeInTheDocument()
  })
  test('cancel remains usable', () => {
    show(); fireEvent.click(screen.getByTestId('revoke-access-cancel-v2'))
    expect(mockClose).toHaveBeenCalledTimes(1)
    expect(kickDevice).not.toHaveBeenCalled()
  })
  test('uses explicit close handler when supplied', () => {
    const close = jest.fn(); show(close)
    fireEvent.click(screen.getByTestId('revoke-access-cancel-v2'))
    expect(close).toHaveBeenCalledTimes(1)
    expect(mockClose).not.toHaveBeenCalled()
  })
})
