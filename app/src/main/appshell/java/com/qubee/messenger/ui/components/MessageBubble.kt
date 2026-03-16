package com.qubee.messenger.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Done
import androidx.compose.material.icons.rounded.DoneAll
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.qubee.messenger.model.ChatMessage
import com.qubee.messenger.model.DeliveryState
import com.qubee.messenger.model.MessageSender

@Composable
fun MessageBubble(message: ChatMessage, modifier: Modifier = Modifier) {
    val isLocal = message.sender == MessageSender.LocalUser
    val bubbleColor = when {
        message.deliveryState == DeliveryState.Failed -> MaterialTheme.colorScheme.error.copy(alpha = 0.22f)
        isLocal -> MaterialTheme.colorScheme.primary
        else -> MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.74f)
    }
    val contentColor = if (isLocal) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface
    val receiptColor = when (message.deliveryState) {
        DeliveryState.Read -> MaterialTheme.colorScheme.tertiary
        DeliveryState.Delivered -> contentColor.copy(alpha = 0.78f)
        DeliveryState.Sent, DeliveryState.Sending -> contentColor.copy(alpha = 0.62f)
        DeliveryState.Failed -> MaterialTheme.colorScheme.error
    }

    Row(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = if (isLocal) Arrangement.End else Arrangement.Start,
    ) {
        Surface(
            shape = RoundedCornerShape(
                topStart = 24.dp,
                topEnd = 24.dp,
                bottomStart = if (isLocal) 24.dp else 8.dp,
                bottomEnd = if (isLocal) 8.dp else 24.dp,
            ),
            color = bubbleColor,
            tonalElevation = 0.dp,
        ) {
            Column(modifier = Modifier.padding(horizontal = 14.dp, vertical = 11.dp)) {
                Text(text = message.body, style = MaterialTheme.typography.bodyLarge, color = contentColor)
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        text = message.formattedTime,
                        style = MaterialTheme.typography.labelSmall,
                        color = contentColor.copy(alpha = 0.72f),
                    )
                    if (isLocal) {
                        ReceiptMeta(message = message, tint = receiptColor)
                    }
                }
            }
        }
    }
}

@Composable
private fun ReceiptMeta(message: ChatMessage, tint: Color) {
    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        when (message.deliveryState) {
            DeliveryState.Read -> Icon(Icons.Rounded.DoneAll, contentDescription = null, tint = tint, modifier = Modifier.padding(top = 1.dp))
            DeliveryState.Delivered -> Icon(Icons.Rounded.DoneAll, contentDescription = null, tint = tint, modifier = Modifier.padding(top = 1.dp))
            DeliveryState.Sent, DeliveryState.Sending -> Icon(Icons.Rounded.Done, contentDescription = null, tint = tint, modifier = Modifier.padding(top = 1.dp))
            DeliveryState.Failed -> Text(text = "failed", style = MaterialTheme.typography.labelSmall, color = tint)
        }
        if (message.deliveredToDeviceCount > 0 || message.readByDeviceCount > 0) {
            Text(
                text = buildString {
                    if (message.deliveredToDeviceCount > 0) append("d:${message.deliveredToDeviceCount}")
                    if (message.readByDeviceCount > 0) {
                        if (isNotEmpty()) append(" ")
                        append("r:${message.readByDeviceCount}")
                    }
                },
                style = MaterialTheme.typography.labelSmall,
                color = tint,
            )
        }
    }
}
