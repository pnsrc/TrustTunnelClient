package me.pnsrc.firetunnel

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Path
import android.util.AttributeSet
import android.view.View
import com.google.android.material.R as MaterialR

/**
 * Live throughput chart for the last [CAPACITY] seconds: download as a filled
 * area, upload as a line, both scaled to the peak in the window.
 */
class SpeedChartView @JvmOverloads constructor(
    context: Context, attrs: AttributeSet? = null
) : View(context, attrs) {

    companion object {
        const val CAPACITY = 60
    }

    private val down = LongArray(CAPACITY)
    private val up = LongArray(CAPACITY)
    private var count = 0
    private var head = 0

    private val density = resources.displayMetrics.density
    private val downFill = Paint(Paint.ANTI_ALIAS_FLAG).apply { style = Paint.Style.FILL }
    private val downLine = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 2.5f * density
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
    }
    private val upLine = Paint(downLine)
    private val path = Path()

    init {
        val primary = UiKit.themeColor(context, androidx.appcompat.R.attr.colorPrimary)
        downLine.color = primary
        downFill.color = primary
        downFill.alpha = 48
        upLine.color = UiKit.themeColor(context, MaterialR.attr.colorTertiary)
        contentDescription = context.getString(R.string.stat_speed)
    }

    fun push(downBps: Long, upBps: Long) {
        down[head] = downBps.coerceAtLeast(0)
        up[head] = upBps.coerceAtLeast(0)
        head = (head + 1) % CAPACITY
        if (count < CAPACITY) count++
        invalidate()
    }

    fun clear() {
        count = 0
        head = 0
        invalidate()
    }

    private fun at(series: LongArray, i: Int): Long = series[(head - count + i + CAPACITY) % CAPACITY]

    override fun onDraw(canvas: Canvas) {
        if (count < 2) return
        val peak = (0 until count).maxOf { maxOf(at(down, it), at(up, it)) }.coerceAtLeast(1024)
        val w = width.toFloat()
        val h = height.toFloat() - downLine.strokeWidth
        val step = w / (CAPACITY - 1)
        val x0 = w - (count - 1) * step
        fun y(v: Long) = downLine.strokeWidth / 2 + h - h * v / peak

        path.rewind()
        path.moveTo(x0, y(at(down, 0)))
        for (i in 1 until count) path.lineTo(x0 + i * step, y(at(down, i)))
        canvas.drawPath(path, downLine)
        path.lineTo(w, height.toFloat())
        path.lineTo(x0, height.toFloat())
        path.close()
        canvas.drawPath(path, downFill)

        path.rewind()
        path.moveTo(x0, y(at(up, 0)))
        for (i in 1 until count) path.lineTo(x0 + i * step, y(at(up, i)))
        canvas.drawPath(path, upLine)
    }
}
