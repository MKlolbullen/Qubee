package com.qubee.messenger.ui.contacts

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.*
import android.widget.Toast
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.lifecycleScope
import androidx.navigation.fragment.findNavController
import androidx.recyclerview.widget.LinearLayoutManager
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.snackbar.Snackbar
import com.qubee.messenger.R
import com.qubee.messenger.databinding.FragmentContactsBinding
import com.qubee.messenger.data.model.Contact
import com.qubee.messenger.data.model.ContactVerificationStatus
import com.qubee.messenger.data.model.TrustLevel
import com.qubee.messenger.ui.contacts.adapter.ContactsAdapter
import com.qubee.messenger.ui.contacts.verification.ContactVerificationActivity
import com.qubee.messenger.util.QRCodeScanner
import com.qubee.messenger.util.NFCManager
import kotlinx.coroutines.launch

/**
 * Enhanced contacts fragment with advanced verification and management features
 */
class ContactsFragment : Fragment() {
    
    private var _binding: FragmentContactsBinding? = null
    private val binding get() = _binding!!
    
    private val viewModel: ContactsViewModel by viewModels()
    private lateinit var contactsAdapter: ContactsAdapter
    private lateinit var qrCodeScanner: QRCodeScanner
    private lateinit var nfcManager: NFCManager
    
    companion object {
        private const val REQUEST_CAMERA_PERMISSION = 1001
        private const val REQUEST_NFC_PERMISSION = 1002
        private const val REQUEST_CONTACTS_PERMISSION = 1003
    }
    
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentContactsBinding.inflate(inflater, container, false)
        return binding.root
    }
    
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        setupRecyclerView()
        setupFab()
        setupSearch()
        setupObservers()
        setupManagers()
        
        // Load contacts
        viewModel.loadContacts()
    }
    
    private fun setupRecyclerView() {
        contactsAdapter = ContactsAdapter(
            onContactClick = { contact ->
                openContactDetails(contact)
            },
            onContactLongClick = { contact ->
                showContactOptions(contact)
            },
            onVerifyClick = { contact ->
                showVerificationOptions(contact)
            },
            onCallClick = { contact ->
                initiateCall(contact, isVideo = false)
            },
            onVideoCallClick = { contact ->
                initiateCall(contact, isVideo = true)
            }
        )
        
        binding.recyclerViewContacts.apply {
            layoutManager = LinearLayoutManager(requireContext())
            adapter = contactsAdapter
        }
    }
    
    private fun setupFab() {
        binding.fabAddContact.setOnClickListener {
            showAddContactOptions()
        }
    }
    
    private fun setupSearch() {
        binding.searchView.setOnQueryTextListener(object : androidx.appcompat.widget.SearchView.OnQueryTextListener {
            override fun onQueryTextSubmit(query: String?): Boolean {
                query?.let { viewModel.searchContacts(it) }
                return true
            }
            
            override fun onQueryTextChange(newText: String?): Boolean {
                newText?.let { viewModel.searchContacts(it) }
                return true
            }
        })
        
        // Trust level filter
        binding.chipGroupTrustLevel.setOnCheckedStateChangeListener { _, checkedIds ->
            val trustLevels = checkedIds.mapNotNull { chipId ->
                when (chipId) {
                    R.id.chip_trust_unknown -> TrustLevel.UNKNOWN
                    R.id.chip_trust_basic -> TrustLevel.BASIC
                    R.id.chip_trust_enhanced -> TrustLevel.ENHANCED
                    R.id.chip_trust_high -> TrustLevel.HIGH
                    R.id.chip_trust_maximum -> TrustLevel.MAXIMUM
                    else -> null
                }
            }
            viewModel.filterByTrustLevel(trustLevels)
        }
    }
    
    private fun setupObservers() {
        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.contacts.collect { contacts ->
                contactsAdapter.submitList(contacts)
                updateEmptyState(contacts.isEmpty())
            }
        }
        
        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.loading.collect { isLoading ->
                binding.progressBar.visibility = if (isLoading) View.VISIBLE else View.GONE
            }
        }
        
        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.error.collect { error ->
                error?.let {
                    Snackbar.make(binding.root, it, Snackbar.LENGTH_LONG).show()
                    viewModel.clearError()
                }
            }
        }
        
        viewLifecycleOwner.lifecycleScope.launch {
            viewModel.verificationResult.collect { result ->
                result?.let {
                    handleVerificationResult(it)
                    viewModel.clearVerificationResult()
                }
            }
        }
    }
    
    private fun setupManagers() {
        qrCodeScanner = QRCodeScanner(this) { qrData ->
            viewModel.verifyContactWithQR(qrData)
        }
        
        nfcManager = NFCManager(requireActivity()) { nfcData ->
            viewModel.verifyContactWithNFC(nfcData)
        }
    }
    
    private fun showAddContactOptions() {
        val options = arrayOf(
            getString(R.string.add_contact_qr_code),
            getString(R.string.add_contact_nfc),
            getString(R.string.add_contact_invite_link),
            getString(R.string.add_contact_manual),
            getString(R.string.add_contact_phone_number)
        )
        
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.add_contact)
            .setItems(options) { _, which ->
                when (which) {
                    0 -> scanQRCode()
                    1 -> useNFC()
                    2 -> enterInviteLink()
                    3 -> addContactManually()
                    4 -> importFromPhoneContacts()
                }
            }
            .show()
    }
    
    private fun scanQRCode() {
        if (ContextCompat.checkSelfPermission(requireContext(), Manifest.permission.CAMERA) 
            != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(
                requireActivity(),
                arrayOf(Manifest.permission.CAMERA),
                REQUEST_CAMERA_PERMISSION
            )
        } else {
            qrCodeScanner.startScanning()
        }
    }
    
    private fun useNFC() {
        if (nfcManager.isNFCAvailable()) {
            nfcManager.enableNFCReading()
            Toast.makeText(requireContext(), R.string.nfc_ready_to_read, Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(requireContext(), R.string.nfc_not_available, Toast.LENGTH_SHORT).show()
        }
    }
    
    private fun enterInviteLink() {
        val dialogView = LayoutInflater.from(requireContext())
            .inflate(R.layout.dialog_invite_link, null)
        
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.enter_invite_link)
            .setView(dialogView)
            .setPositiveButton(R.string.add) { _, _ ->
                val editText = dialogView.findViewById<com.google.android.material.textfield.TextInputEditText>(R.id.edit_invite_link)
                val inviteLink = editText.text.toString().trim()
                if (inviteLink.isNotEmpty()) {
                    viewModel.addContactFromInviteLink(inviteLink)
                }
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }
    
    private fun addContactManually() {
        findNavController().navigate(R.id.action_contacts_to_add_contact_manual)
    }
    
    private fun importFromPhoneContacts() {
        if (ContextCompat.checkSelfPermission(requireContext(), Manifest.permission.READ_CONTACTS) 
            != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(
                requireActivity(),
                arrayOf(Manifest.permission.READ_CONTACTS),
                REQUEST_CONTACTS_PERMISSION
            )
        } else {
            findNavController().navigate(R.id.action_contacts_to_import_contacts)
        }
    }
    
    private fun showContactOptions(contact: Contact) {
        val options = mutableListOf<String>().apply {
            add(getString(R.string.view_details))
            add(getString(R.string.send_message))
            add(getString(R.string.voice_call))
            add(getString(R.string.video_call))
            
            if (contact.verificationStatus != ContactVerificationStatus.VERIFIED_MULTIPLE) {
                add(getString(R.string.verify_contact))
            }
            
            add(getString(R.string.edit_contact))
            add(getString(R.string.block_contact))
            add(getString(R.string.delete_contact))
        }
        
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(contact.displayName)
            .setItems(options.toTypedArray()) { _, which ->
                when (options[which]) {
                    getString(R.string.view_details) -> openContactDetails(contact)
                    getString(R.string.send_message) -> openChat(contact)
                    getString(R.string.voice_call) -> initiateCall(contact, false)
                    getString(R.string.video_call) -> initiateCall(contact, true)
                    getString(R.string.verify_contact) -> showVerificationOptions(contact)
                    getString(R.string.edit_contact) -> editContact(contact)
                    getString(R.string.block_contact) -> blockContact(contact)
                    getString(R.string.delete_contact) -> deleteContact(contact)
                }
            }
            .show()
    }
    
    private fun showVerificationOptions(contact: Contact) {
        val options = arrayOf(
            getString(R.string.verify_qr_code),
            getString(R.string.verify_nfc),
            getString(R.string.verify_zk_proof),
            getString(R.string.verify_video_call),
            getString(R.string.verify_shared_secret)
        )
        
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(getString(R.string.verify_contact_title, contact.displayName))
            .setItems(options) { _, which ->
                when (which) {
                    0 -> verifyWithQRCode(contact)
                    1 -> verifyWithNFC(contact)
                    2 -> verifyWithZKProof(contact)
                    3 -> verifyWithVideoCall(contact)
                    4 -> verifyWithSharedSecret(contact)
                }
            }
            .show()
    }
    
    private fun verifyWithQRCode(contact: Contact) {
        val intent = ContactVerificationActivity.createIntent(
            requireContext(),
            contact.identityId,
            ContactVerificationActivity.VerificationMethod.QR_CODE
        )
        startActivity(intent)
    }
    
    private fun verifyWithNFC(contact: Contact) {
        val intent = ContactVerificationActivity.createIntent(
            requireContext(),
            contact.identityId,
            ContactVerificationActivity.VerificationMethod.NFC
        )
        startActivity(intent)
    }
    
    private fun verifyWithZKProof(contact: Contact) {
        val intent = ContactVerificationActivity.createIntent(
            requireContext(),
            contact.identityId,
            ContactVerificationActivity.VerificationMethod.ZK_PROOF
        )
        startActivity(intent)
    }
    
    private fun verifyWithVideoCall(contact: Contact) {
        // Start video call with verification mode
        viewModel.initiateVerificationCall(contact.identityId)
    }
    
    private fun verifyWithSharedSecret(contact: Contact) {
        val intent = ContactVerificationActivity.createIntent(
            requireContext(),
            contact.identityId,
            ContactVerificationActivity.VerificationMethod.SHARED_SECRET
        )
        startActivity(intent)
    }
    
    private fun openContactDetails(contact: Contact) {
        val action = ContactsFragmentDirections.actionContactsToContactDetails(contact.identityId)
        findNavController().navigate(action)
    }
    
    private fun openChat(contact: Contact) {
        val action = ContactsFragmentDirections.actionContactsToChat(contact.identityId)
        findNavController().navigate(action)
    }
    
    private fun initiateCall(contact: Contact, isVideo: Boolean) {
        viewModel.initiateCall(contact.identityId, isVideo)
    }
    
    private fun editContact(contact: Contact) {
        val action = ContactsFragmentDirections.actionContactsToEditContact(contact.identityId)
        findNavController().navigate(action)
    }
    
    private fun blockContact(contact: Contact) {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.block_contact)
            .setMessage(getString(R.string.block_contact_confirmation, contact.displayName))
            .setPositiveButton(R.string.block) { _, _ ->
                viewModel.blockContact(contact.identityId)
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }
    
    private fun deleteContact(contact: Contact) {
        MaterialAlertDialogBuilder(requireContext())
            .setTitle(R.string.delete_contact)
            .setMessage(getString(R.string.delete_contact_confirmation, contact.displayName))
            .setPositiveButton(R.string.delete) { _, _ ->
                viewModel.deleteContact(contact.identityId)
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }
    
    private fun handleVerificationResult(result: ContactVerificationResult) {
        val message = when (result.success) {
            true -> getString(R.string.verification_successful, result.contactName)
            false -> getString(R.string.verification_failed, result.error)
        }
        
        Snackbar.make(binding.root, message, Snackbar.LENGTH_LONG).show()
        
        if (result.success) {
            // Refresh contacts to show updated verification status
            viewModel.loadContacts()
        }
    }
    
    private fun updateEmptyState(isEmpty: Boolean) {
        binding.emptyStateGroup.visibility = if (isEmpty) View.VISIBLE else View.GONE
        binding.recyclerViewContacts.visibility = if (isEmpty) View.GONE else View.VISIBLE
    }
    
    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        
        when (requestCode) {
            REQUEST_CAMERA_PERMISSION -> {
                if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                    qrCodeScanner.startScanning()
                } else {
                    Toast.makeText(requireContext(), R.string.camera_permission_required, Toast.LENGTH_SHORT).show()
                }
            }
            REQUEST_CONTACTS_PERMISSION -> {
                if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                    findNavController().navigate(R.id.action_contacts_to_import_contacts)
                } else {
                    Toast.makeText(requireContext(), R.string.contacts_permission_required, Toast.LENGTH_SHORT).show()
                }
            }
        }
    }
    
    override fun onResume() {
        super.onResume()
        nfcManager.enableNFCReading()
    }
    
    override fun onPause() {
        super.onPause()
        nfcManager.disableNFCReading()
    }
    
    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}

/**
 * Data class for contact verification results
 */
data class ContactVerificationResult(
    val success: Boolean,
    val contactName: String,
    val verificationMethod: String,
    val error: String? = null
)

live
