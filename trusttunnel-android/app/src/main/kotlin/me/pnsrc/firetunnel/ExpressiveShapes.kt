package me.pnsrc.firetunnel

import android.animation.ArgbEvaluator
import android.animation.ValueAnimator
import android.graphics.Canvas
import android.graphics.ColorFilter
import android.graphics.Matrix
import android.graphics.Paint
import android.graphics.Path
import android.graphics.PixelFormat
import android.graphics.drawable.Drawable
import android.view.animation.OvershootInterpolator
import androidx.graphics.shapes.CornerRounding
import androidx.graphics.shapes.Morph
import androidx.graphics.shapes.RoundedPolygon
import androidx.graphics.shapes.circle
import androidx.graphics.shapes.star
import androidx.graphics.shapes.toPath
import androidx.graphics.shapes.transformed

/**
 * Material 3 Expressive shapes built with the public graphics-shapes API
 * (same parameters as Material's own shape library), normalised to the unit
 * square centred at (0.5, 0.5) so they can rotate in place.
 */
object ExpressiveShapes {
    val COOKIE_9: RoundedPolygon = unit(RoundedPolygon.star(9, 1f, 0.8f, CornerRounding(0.5f)), rotate = -90f)
    val COOKIE_12: RoundedPolygon = unit(RoundedPolygon.star(12, 1f, 0.8f, CornerRounding(0.5f)), rotate = -90f)
    val SUNNY: RoundedPolygon = unit(RoundedPolygon.star(8, 1f, 0.8f, CornerRounding(0.15f)))
    val BURST: RoundedPolygon = unit(RoundedPolygon.star(10, 1f, 0.7f, CornerRounding(0.12f)))
    val CIRCLE: RoundedPolygon = unit(RoundedPolygon.circle(10))

    private fun unit(shape: RoundedPolygon, rotate: Float = 0f): RoundedPolygon {
        val rotated = if (rotate == 0f) shape else shape.transformed(Matrix().apply { setRotate(rotate) })
        val b = rotated.calculateMaxBounds()
        val scale = 1f / maxOf(b[2] - b[0], b[3] - b[1])
        val m = Matrix().apply {
            setScale(scale, scale)
            preTranslate(-(b[0] + b[2]) / 2f, -(b[1] + b[3]) / 2f)
            postTranslate(0.5f, 0.5f)
        }
        return rotated.transformed(m)
    }
}

/**
 * Fills its bounds with a shape that morphs between [ExpressiveShapes] with a
 * springy overshoot, cross-fades its colour and can spin around its centre.
 */
class MorphShapeDrawable(initial: RoundedPolygon, color: Int) : Drawable() {

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply { this.color = color }
    private val path = Path()
    private val matrix = Matrix()
    private var target = initial
    private var morph = Morph(initial, initial)
    private var progress = 1f
    private var morphAnimator: ValueAnimator? = null
    private var colorAnimator: ValueAnimator? = null

    /** Rotation in degrees around the centre. */
    var rotation = 0f
        set(value) {
            field = value
            invalidateSelf()
        }

    fun morphTo(shape: RoundedPolygon, animate: Boolean = true) {
        if (shape === target) return
        morphAnimator?.cancel()
        morph = Morph(target, shape)
        target = shape
        if (!animate) {
            progress = 1f
            invalidateSelf()
            return
        }
        morphAnimator = ValueAnimator.ofFloat(0f, 1f).apply {
            duration = 650
            interpolator = OvershootInterpolator(1.6f)
            addUpdateListener {
                progress = it.animatedValue as Float
                invalidateSelf()
            }
            start()
        }
    }

    fun setColor(color: Int, animate: Boolean = true) {
        colorAnimator?.cancel()
        if (!animate || paint.color == color) {
            paint.color = color
            invalidateSelf()
            return
        }
        colorAnimator = ValueAnimator.ofObject(ArgbEvaluator(), paint.color, color).apply {
            duration = 350
            addUpdateListener {
                paint.color = it.animatedValue as Int
                invalidateSelf()
            }
            start()
        }
    }

    override fun draw(canvas: Canvas) {
        val b = bounds
        if (b.isEmpty) return
        path.rewind()
        morph.toPath(progress, path)
        matrix.setScale(b.width().toFloat(), b.height().toFloat())
        matrix.postTranslate(b.left.toFloat(), b.top.toFloat())
        path.transform(matrix)
        canvas.save()
        canvas.rotate(rotation, b.exactCenterX(), b.exactCenterY())
        canvas.drawPath(path, paint)
        canvas.restore()
    }

    override fun setAlpha(alpha: Int) {
        paint.alpha = alpha
        invalidateSelf()
    }

    override fun setColorFilter(colorFilter: ColorFilter?) {
        paint.colorFilter = colorFilter
        invalidateSelf()
    }

    @Deprecated("Deprecated in Java")
    override fun getOpacity(): Int = PixelFormat.TRANSLUCENT
}
